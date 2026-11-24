package sbom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/quay/claircore"
)

// defaultFlushBytes bounds the per-request output buffer. It is sized to hold a
// handful of typical components while keeping memory use flat for large
// reports: a 100k-package export still holds at most this much encoded output
// between flushes.
const defaultFlushBytes = 64 * 1024

// component is the fully-resolved, export-ready view of one package. It is the
// unit of streaming work: the report is walked package-by-package and each
// component is encoded and flushed independently.
type component struct {
	bomRef  string
	cdxType componentType
	name    string
	version string
	purl    string
	cpe     string
	arch    string
	source  bool
	// sourceRef is the bom-ref of the component's source package, when the
	// source package is itself present in the report.
	sourceRef string
	// properties, already in document order.
	properties [][2]string
	// layerRefs are the bom-refs of layers the package was introduced in,
	// sorted and deduplicated.
	layerRefs []string
}

// layerComponent is an export-ready view of an image layer.
type layerComponent struct {
	bomRef string
	digest string
}

// countedWriter wraps an [io.Writer] and observes the total number of bytes
// written, so streaming behavior is observable in tests.
type countedWriter struct {
	w            io.Writer
	bytesWritten int64
}

func (c *countedWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.bytesWritten += int64(n)
	return n, err
}

// flushWriter buffers writes and flushes to its underlying writer whenever the
// buffered size crosses its bound. Each encoded component is handed to it in a
// single Write, so nothing larger than one component plus the bounded buffer is
// ever resident, regardless of the total document size.
type flushWriter struct {
	w         io.Writer
	buf       bytes.Buffer
	bound     int
	flushes   int
	highWater int64
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.buf.Write(p)
	if int64(f.buf.Len()) > f.highWater {
		f.highWater = int64(f.buf.Len())
	}
	if f.buf.Len() >= f.bound {
		if ferr := f.Flush(); ferr != nil && err == nil {
			err = ferr
		}
	}
	return n, err
}

// Flush writes any buffered data to the underlying writer.
func (f *flushWriter) Flush() error {
	if f.buf.Len() == 0 {
		return nil
	}
	if _, err := f.buf.WriteTo(f.w); err != nil {
		return err
	}
	f.flushes++
	return nil
}

// streamWriter is the narrow writing interface used while rendering a document.
// Raw structural punctuation goes through raw; complete JSON values go through
// value and are marshaled with the standard library so all quoting and escaping
// stays correct.
type streamWriter struct {
	ctx context.Context
	fw  *flushWriter
}

func (s *streamWriter) raw(p string) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	_, err := s.fw.Write([]byte(p))
	return err
}

func (s *streamWriter) value(v any) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	b, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	_, err = s.fw.Write(b)
	return err
}

// jsonMarshal marshals without HTML escaping, matching the document-wide
// convention.
func jsonMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a trailing newline that must not reach the document.
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// exportCycloneDX renders a deterministic, streaming CycloneDX 1.6 JSON
// document.
//
// Streaming contract: packages are resolved one at a time from the sorted
// package IDs and each component is encoded and flushed as soon as it is
// finalized. Only a set of already-emitted bom-refs (needed for dedup and for
// the dependency list) is retained, never the components or the assembled
// document. Memory therefore grows with the number of distinct refs, not with
// the encoded output size, and the output buffer stays within the configured
// flush bound.
//
// Determinism contract (all collections are covered):
//   - package components are ordered by their stable bom-ref;
//   - layer components are ordered by digest string;
//   - within a package, layer references and properties are sorted;
//   - a package appearing in multiple layers (or multiple environments) is
//     emitted exactly once, with merged layer references;
//   - map iteration over the index report never reaches the output directly.
func (e *Exporter) exportCycloneDX(ctx context.Context, w io.Writer, r *Report, opts *Options) (Stats, error) {
	filter := Filter{}
	if opts != nil {
		filter = opts.Filter
	}
	flushBound := e.flushBytes
	if opts != nil && opts.FlushBytes > 0 {
		flushBound = opts.FlushBytes
	}

	// Resolve the layer list first: layer components are emitted before package
	// components and are referenced by bom-ref.
	layers, layerRefs := e.resolveLayers(r, filter)

	// The planning pass walks and validates every package before any byte is
	// written. All content-level errors therefore surface before the response
	// starts, so a half document can only result from a transport failure
	// (such as the client disconnecting) once streaming begins.
	//
	// Metadata needs the final skip count, which is only known after this walk.
	// The plan records only small bookkeeping (refs, counters, merged layers);
	// the second pass re-resolves and streams components one at a time.
	planned, stats, err := e.planComponents(ctx, r, filter, layerRefs)
	if err != nil {
		return Stats{}, err
	}
	stats.Layers = len(layers)

	cw := &countedWriter{w: w}
	fw := &flushWriter{w: cw, bound: flushBound}
	sw := &streamWriter{ctx: ctx, fw: fw}

	// Sections are joined with leading commas, so the document never carries a
	// trailing comma before the closing brace.
	//
	// Document preamble. No timestamp or serial number is emitted: both would
	// break byte-for-byte stability across repeated exports of the same report.
	if err := sw.raw(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":%q,"version":1`, SpecVersion)); err != nil {
		return Stats{}, err
	}

	if err := e.writeMetadata(sw, r, stats, filter); err != nil {
		return Stats{}, err
	}

	if len(layers) > 0 || len(planned.refs) > 0 {
		if err := sw.raw(`,"components":[`); err != nil {
			return Stats{}, err
		}
		first := true
		for _, l := range layers {
			if err := sw.raw(separator(first)); err != nil {
				return Stats{}, err
			}
			first = false
			if err := sw.value(newLayerValue(l)); err != nil {
				return Stats{}, err
			}
		}
		// Package components are re-resolved one at a time and streamed in
		// bom-ref order. The plan tells the resolver which refs survive and in
		// what order; nothing larger than one component is resident at once.
		if err := e.streamComponents(ctx, sw, r, filter, layerRefs, planned, &first); err != nil {
			return Stats{}, err
		}
		if err := sw.raw(`]`); err != nil {
			return Stats{}, err
		}
	}

	if len(planned.refs) > 0 {
		if err := e.writeDependencies(sw, r, planned.refs); err != nil {
			return Stats{}, err
		}
	}

	if r.State != "IndexFinished" {
		// An index whose state is not the terminal "IndexFinished" state only
		// covers part of the image, so the document is explicitly marked
		// incomplete rather than presented as exhaustive.
		if err := sw.raw(`,"compositions":`); err != nil {
			return Stats{}, err
		}
		if err := sw.value([]composition{{
			BOMRefs: []string{imageBOMRef(r.Hash.String())},
			Type:    "incomplete",
		}}); err != nil {
			return Stats{}, err
		}
	}

	if err := sw.raw(`}`); err != nil {
		return Stats{}, err
	}
	if err := fw.Flush(); err != nil {
		return Stats{}, err
	}

	stats.FlushCount = fw.flushes
	stats.BytesWritten = cw.bytesWritten
	stats.Buffered = fw.highWater
	return stats, nil
}

// componentPlan holds the small, ref-only bookkeeping produced by the planning
// pass. It deliberately stores no component payloads.
type componentPlan struct {
	// refs is the sorted list of bom-refs that make it into the document, in
	// emission order.
	refs []string
	// emitted records refs already accepted, for dedup.
	emitted map[string]struct{}
	// layers records the merged, sorted layer bom-refs for each emitted
	// component. A package seen in several layers contributes all its layers to
	// the single component that represents it. Only short ref strings are held.
	layers map[string][]string
}

// planComponents performs the first pass over the sorted package IDs. It counts
// skipped packages and records the bom-refs (only the refs) to emit, in sorted
// order. No component objects are retained.
func (e *Exporter) planComponents(ctx context.Context, r *Report, f Filter, layerRefs map[string]string) (componentPlan, Stats, error) {
	typeWanted := stringSet(f.Types)
	layerWanted := stringSet(f.Layers)
	var stats Stats
	plan := componentPlan{
		emitted: make(map[string]struct{}),
		layers:  make(map[string][]string),
	}

	for _, id := range r.sortedPackageIDs() {
		if err := ctx.Err(); err != nil {
			return componentPlan{}, Stats{}, err
		}
		c, ok, reason := e.resolveOne(ctx, r, f, typeWanted, layerWanted, layerRefs, id)
		if !ok {
			if reason == skipMalformed {
				stats.Skipped++
			}
			continue
		}
		if _, dup := plan.emitted[c.bomRef]; dup {
			// Same logical package reached through another layer/environment.
			// Merge its layer references into the single component.
			plan.layers[c.bomRef] = sortedUnique(append(plan.layers[c.bomRef], c.layerRefs...))
			continue
		}
		plan.emitted[c.bomRef] = struct{}{}
		plan.refs = append(plan.refs, c.bomRef)
		plan.layers[c.bomRef] = append([]string(nil), c.layerRefs...)
		stats.Components++
	}
	sort.Strings(plan.refs)
	return plan, stats, nil
}

// streamComponents performs the streaming second pass, re-resolving each
// surviving package on demand and writing it immediately.
func (e *Exporter) streamComponents(ctx context.Context, sw *streamWriter, r *Report, f Filter, layerRefs map[string]string, plan componentPlan, first *bool) error {
	typeWanted := stringSet(f.Types)
	layerWanted := stringSet(f.Layers)
	written := make(map[string]struct{}, len(plan.refs))
	for _, id := range r.sortedPackageIDs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, ok, _ := e.resolveOne(ctx, r, f, typeWanted, layerWanted, layerRefs, id)
		if !ok {
			continue
		}
		if _, wanted := plan.emitted[c.bomRef]; !wanted {
			continue
		}
		if _, done := written[c.bomRef]; done {
			// Duplicate across layers/environments: its layers were merged during
			// planning, so it is emitted exactly once.
			continue
		}
		written[c.bomRef] = struct{}{}
		// Use the plan's merged layer set, which may include layers observed on
		// duplicate occurrences of the same package.
		c.layerRefs = plan.layers[c.bomRef]
		if err := sw.raw(separator(*first)); err != nil {
			return err
		}
		*first = false
		if err := sw.value(newComponentValue(c)); err != nil {
			return err
		}
	}
	return nil
}

// skipReason explains why a package produced no component.
type skipReason int

const (
	skipNone skipReason = iota
	// skipMalformed: a required field (name, version, ecosystem) is missing.
	// These are counted in Stats.Skipped.
	skipMalformed
	// skipFiltered: the package is well-formed but excluded by an explicit
	// type or layer filter. These are not counted as malformed.
	skipFiltered
)

// resolveOne resolves a single package ID into an export-ready component.
//
// When the package does not produce a component, ok is false and reason says
// whether it was malformed (counted as a skip) or merely filtered out.
func (e *Exporter) resolveOne(
	ctx context.Context,
	r *Report,
	_ Filter,
	typeWanted, layerWanted map[string]struct{},
	layerRefs map[string]string,
	id string,
) (component, bool, skipReason) {
	p := r.pkgs[id]
	if p == nil {
		return component{}, false, skipMalformed
	}
	// Required fields: a package without name, version or a recognizable
	// ecosystem cannot be represented honestly and is skipped.
	eco, ok := ecosystemFor(p)
	if !ok || p.Name == "" || p.Version == "" {
		slog.DebugContext(ctx, "skipping package with missing fields",
			"package_id", id, "name", p.Name, "has_version", p.Version != "")
		return component{}, false, skipMalformed
	}
	if len(typeWanted) > 0 {
		if _, ok := typeWanted[eco.purlType]; !ok {
			return component{}, false, skipFiltered
		}
	}

	// Resolve layer references for every environment the package appears in.
	// A package introduced in several layers is still one component.
	var refs []string
	var dist *claircore.Distribution
	for _, env := range r.environmentsFor(id) {
		if env == nil {
			continue
		}
		if d := r.dists[env.DistributionID]; d != nil && dist == nil {
			dist = d
		}
		dstr := env.IntroducedIn.String()
		if dstr == "" {
			continue
		}
		if len(layerWanted) > 0 {
			if _, ok := layerWanted[dstr]; !ok {
				continue
			}
		}
		if ref, ok := layerRefs[dstr]; ok {
			refs = append(refs, ref)
		}
	}
	// When a layer filter is active, a package with no environment in a
	// selected layer is excluded rather than malformed.
	if len(layerWanted) > 0 && len(refs) == 0 {
		return component{}, false, skipFiltered
	}
	refs = sortedUnique(refs)

	purl, err := makePURL(eco, p, dist)
	if err != nil {
		slog.DebugContext(ctx, "skipping package with unparsable coordinates",
			"package_id", id, "reason", err)
		return component{}, false, skipMalformed
	}

	c := component{
		bomRef:    packageBOMRef(eco, purl.String()),
		cdxType:   eco.cdxType,
		name:      p.Name,
		version:   p.Version,
		purl:      purl.String(),
		arch:      p.Arch,
		source:    isSourcePackage(p),
		layerRefs: refs,
	}
	if cpe := p.CPE.String(); cpe != "" {
		c.cpe = cpe
	}
	if p.Source != nil && p.Source.Name != "" {
		// Source-package linkage is derived only from the report's own data:
		// link by bom-ref when the source package is itself in the report,
		// otherwise record its coordinates as a property.
		if sp, ok := r.pkgs[p.Source.ID]; ok && sp.Name != "" && sp.Version != "" {
			if seco, sok := ecosystemFor(sp); sok {
				if spurl, err := makePURL(seco, sp, dist); err == nil {
					c.sourceRef = packageBOMRef(seco, spurl.String())
				}
			}
		}
		if c.sourceRef == "" {
			c.properties = append(c.properties, [2]string{"clair:source_package", p.Source.Name + "@" + p.Source.Version})
		}
	}
	if p.Module != "" {
		c.properties = append(c.properties, [2]string{"clair:module", p.Module})
	}
	if eco.distro && dist != nil && dist.PrettyName != "" {
		c.properties = append(c.properties, [2]string{"clair:distribution", dist.PrettyName})
	}
	// Keep properties sorted for byte stability; the name+value key is total.
	sort.Slice(c.properties, func(i, j int) bool {
		if c.properties[i][0] != c.properties[j][0] {
			return c.properties[i][0] < c.properties[j][0]
		}
		return c.properties[i][1] < c.properties[j][1]
	})
	return c, true, skipNone
}

// separator returns the JSON array separator for the next element.
func separator(first bool) string {
	if first {
		return ""
	}
	return ","
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type imageHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type imageComp struct {
	Type   string      `json:"type"`
	BOMRef string      `json:"bom-ref"`
	Name   string      `json:"name"`
	Hashes []imageHash `json:"hashes"`
}

type metadataValue struct {
	Component  imageComp  `json:"component"`
	Properties []property `json:"properties"`
}

// writeMetadata emits the metadata object, including the container component
// describing the image and the properties that document index state, skipped
// packages and the absence of dependency data.
func (e *Exporter) writeMetadata(sw *streamWriter, r *Report, stats Stats, f Filter) error {
	props := []property{
		{Name: "clair:dependency_data", Value: "unavailable"},
		{Name: "clair:index_state", Value: r.State},
		{Name: "clair:packages_skipped", Value: fmt.Sprintf("%d", stats.Skipped)},
	}
	if len(f.Types) > 0 || len(f.Layers) > 0 {
		props = append(props, property{Name: "clair:filtered", Value: "true"})
	}
	meta := metadataValue{
		Component: imageComp{
			Type:   "container",
			BOMRef: imageBOMRef(r.Hash.String()),
			Name:   r.Hash.String(),
			Hashes: []imageHash{{
				Alg:     hashAlg(r.Hash.Algorithm()),
				Content: hex.EncodeToString(r.Hash.Checksum()),
			}},
		},
		Properties: props,
	}
	if err := sw.raw(`,"metadata":`); err != nil {
		return err
	}
	return sw.value(meta)
}

type composition struct {
	BOMRefs []string `json:"bom-refs"`
	Type    string   `json:"type"`
}

// writeDependencies emits the dependency array.
//
// Clair index reports carry no package dependency graph, so the export does not
// invent package-to-package edges: the only relationship asserted is the
// well-defined "image contains components" marker, as a single dependency entry
// whose ref is the image component and whose dependsOn lists every package
// component.
//
// The dependsOn array is streamed entry by entry, so a large image never
// materializes a single giant serialization.
func (e *Exporter) writeDependencies(sw *streamWriter, r *Report, refs []string) error {
	if err := sw.raw(`,"dependencies":[{"ref":`); err != nil {
		return err
	}
	ref, err := jsonMarshal(imageBOMRef(r.Hash.String()))
	if err != nil {
		return err
	}
	if _, err := sw.fw.Write(ref); err != nil {
		return err
	}
	if err := sw.raw(`,"dependsOn":[`); err != nil {
		return err
	}
	for i, depRef := range refs {
		if i > 0 {
			if err := sw.raw(`,`); err != nil {
				return err
			}
		}
		b, err := jsonMarshal(depRef)
		if err != nil {
			return err
		}
		if _, err := sw.fw.Write(b); err != nil {
			return err
		}
	}
	return sw.raw(`]}]`)
}

// resolveLayers applies the layer filter and returns the sorted layer
// components together with a digest-to-bom-ref lookup.
func (e *Exporter) resolveLayers(r *Report, f Filter) ([]layerComponent, map[string]string) {
	wanted := stringSet(f.Layers)
	refs := make(map[string]string, len(r.layers))
	var out []layerComponent
	for _, d := range r.sortedLayers() {
		if len(wanted) > 0 {
			if _, ok := wanted[d]; !ok {
				continue
			}
		}
		ref := layerBOMRef(d)
		refs[d] = ref
		out = append(out, layerComponent{bomRef: ref, digest: d})
	}
	return out, refs
}

// componentValue is the on-wire representation of a package component, with a
// fixed key order.
type componentValue struct {
	BOMRef     string          `json:"bom-ref"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	PURL       string          `json:"purl,omitempty"`
	CPE        string          `json:"cpe,omitempty"`
	Components []layerRefValue `json:"components,omitempty"`
	Properties []property      `json:"properties,omitempty"`
}

type layerRefValue struct {
	BOMRef string `json:"bom-ref"`
	Type   string `json:"type"`
}

func newComponentValue(c component) componentValue {
	v := componentValue{
		BOMRef:  c.bomRef,
		Type:    string(c.cdxType),
		Name:    c.name,
		Version: c.version,
		PURL:    c.purl,
		CPE:     c.cpe,
	}
	for _, ref := range c.layerRefs {
		v.Components = append(v.Components, layerRefValue{BOMRef: ref, Type: "file"})
	}
	if c.arch != "" {
		v.Properties = append(v.Properties, property{Name: "clair:arch", Value: c.arch})
	}
	if c.source {
		v.Properties = append(v.Properties, property{Name: "clair:package_kind", Value: "source"})
	}
	if c.sourceRef != "" {
		v.Properties = append(v.Properties, property{Name: "clair:source_package_ref", Value: c.sourceRef})
	}
	for _, p := range c.properties {
		v.Properties = append(v.Properties, property{Name: p[0], Value: p[1]})
	}
	return v
}

// layerValue is the on-wire representation of a layer component.
type layerValue struct {
	BOMRef string `json:"bom-ref"`
	Type   string `json:"type"`
	Name   string `json:"name"`
}

func newLayerValue(l layerComponent) layerValue {
	return layerValue{BOMRef: l.bomRef, Type: "file", Name: l.digest}
}

// Stable bom-ref construction.
//
// Refs are content-derived (never random or map-order dependent), so the same
// index report exported twice yields identical refs. A SHA-256 prefix keeps
// refs compact while avoiding collisions across ecosystems.

func packageBOMRef(eco ecosystem, purl string) string {
	sum := sha256.Sum256([]byte(eco.purlType + ":" + purl))
	return "pkg-" + hex.EncodeToString(sum[:16])
}

func layerBOMRef(digest string) string {
	sum := sha256.Sum256([]byte("layer:" + digest))
	return "layer-" + hex.EncodeToString(sum[:16])
}

func imageBOMRef(digest string) string {
	sum := sha256.Sum256([]byte("image:" + digest))
	return "image-" + hex.EncodeToString(sum[:16])
}

// hashAlg maps Clair digest algorithm names to CycloneDX hash algorithm names.
func hashAlg(algo string) string {
	switch algo {
	case "sha256":
		return "SHA-256"
	case "sha512":
		return "SHA-512"
	default:
		return algo
	}
}

// sortedUnique returns s sorted lexicographically with duplicates removed.
func sortedUnique(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sort.Strings(s)
	out := s[:0]
	var last string
	for i, v := range s {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}

// stringSet builds a lookup set from a list of values.
func stringSet(vs []string) map[string]struct{} {
	if len(vs) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(vs))
	for _, v := range vs {
		m[v] = struct{}{}
	}
	return m
}
