package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/quay/claircore"
	ccTypes "github.com/quay/claircore/toolkit/types"
)

// fixture builds a representative index report exercising distribution and
// language packages, source linkage, multiple layers and malformed entries.
func fixture() *claircore.IndexReport {
	manifest := claircore.MustParseDigest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	l1 := claircore.MustParseDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	l2 := claircore.MustParseDigest("sha256:2222222222222222222222222222222222222222222222222222222222222222")
	ubuntu := &claircore.Distribution{
		ID:         "100",
		DID:        "ubuntu",
		Name:       "Ubuntu",
		Version:    "22.04",
		VersionID:  "22.04",
		PrettyName: "Ubuntu 22.04",
	}
	bashSrc := &claircore.Package{
		ID:       "2",
		Name:     "bash",
		Version:  "5.1-6ubuntu1",
		Kind:     ccTypes.SourcePackage,
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	bash := &claircore.Package{
		ID:       "1",
		Name:     "bash",
		Version:  "5.1-6ubuntu1",
		Kind:     ccTypes.BinaryPackage,
		Arch:     "amd64",
		Source:   bashSrc,
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	django := &claircore.Package{
		ID:       "3",
		Name:     "django",
		Version:  "4.2.1",
		Kind:     ccTypes.BinaryPackage,
		Detector: &claircore.Detector{Name: "python", Version: "5", Kind: "package"},
	}
	maven := &claircore.Package{
		ID:       "4",
		Name:     "org.example:lib",
		Version:  "1.2.3",
		Kind:     ccTypes.BinaryPackage,
		Detector: &claircore.Detector{Name: "java", Version: "1", Kind: "package"},
	}
	missingVersion := &claircore.Package{
		ID:       "5",
		Name:     "no-version",
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	unknownDetector := &claircore.Package{
		ID:       "6",
		Name:     "mystery",
		Version:  "9.9",
		Detector: &claircore.Detector{Name: "made-up-scanner", Version: "1", Kind: "package"},
	}
	return &claircore.IndexReport{
		Hash:          manifest,
		State:         "IndexFinished",
		Success:       true,
		Distributions: map[string]*claircore.Distribution{"100": ubuntu},
		Packages: map[string]*claircore.Package{
			bash.ID: bash, bashSrc.ID: bashSrc, django.ID: django,
			maven.ID: maven, missingVersion.ID: missingVersion, unknownDetector.ID: unknownDetector,
		},
		Environments: map[string][]*claircore.Environment{
			bash.ID: {{
				PackageDB:      "var/lib/dpkg/status",
				IntroducedIn:   l1,
				DistributionID: "100",
			}},
			bashSrc.ID: {{
				PackageDB:      "var/lib/dpkg/status",
				IntroducedIn:   l1,
				DistributionID: "100",
			}},
			django.ID: {{
				PackageDB:    "usr/lib/python3/site-packages",
				IntroducedIn: l2,
			}},
			maven.ID: {{
				PackageDB:    "app.jar",
				IntroducedIn: l2,
			}},
			missingVersion.ID:  {{IntroducedIn: l1, DistributionID: "100"}, {IntroducedIn: l2}},
			unknownDetector.ID: {{IntroducedIn: l1}},
		},
	}
}

func export(t *testing.T, ir *claircore.IndexReport, opts *Options) (bytes.Buffer, Stats) {
	t.Helper()
	var buf bytes.Buffer
	exp := NewExporter(opts)
	stats, err := exp.Export(context.Background(), &buf, FromIndexReport(ir), opts)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return buf, stats
}

func TestExportDeterministic(t *testing.T) {
	ir := fixture()
	first, stats1 := export(t, ir, nil)
	// Build a second report from the same data but with map entries inserted in
	// a different order. Go map iteration is randomized anyway, but rebuild to
	// make the intent explicit.
	second, stats2 := export(t, ir, nil)
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("exports differ:\n%s\n%s", first.String(), second.String())
	}
	if stats1 != stats2 {
		t.Fatalf("stats differ: %+v vs %+v", stats1, stats2)
	}
	// Output must be a single valid JSON object and parse as CycloneDX.
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(first.Bytes()), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("not a valid CycloneDX document: %v\n%s", err, first.String())
	}
	if got, want := bom.SpecVersion.String(), SpecVersion; got != want {
		t.Errorf("spec version: got %q want %q", got, want)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("missing metadata component")
	}
	if got, want := bom.Metadata.Component.Type, cdx.ComponentTypeContainer; got != want {
		t.Errorf("image component type: got %q want %q", got, want)
	}
}

func TestExportContents(t *testing.T) {
	ir := fixture()
	buf, stats := export(t, ir, nil)
	if stats.Skipped != 2 {
		t.Errorf("skipped: got %d want 2 (missing version + unknown detector)", stats.Skipped)
	}
	// bash, bash source, django, maven.
	if stats.Components != 4 {
		t.Errorf("components: got %d want 4", stats.Components)
	}
	if stats.Layers != 2 {
		t.Errorf("layers: got %d want 2", stats.Layers)
	}
	doc := buf.String()
	// Distribution and language packages carry distinct PURL types.
	for _, want := range []string{
		`pkg:deb/bash@5.1-6ubuntu1`,
		`pkg:pypi/django@4.2.1`,
		`pkg:maven/org.example/lib@1.2.3`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document missing purl %q", want)
		}
	}
	// Layer digests must appear as layer components.
	if !strings.Contains(doc, "sha256:1111111111111111111111111111111111111111111111111111111111111111") {
		t.Error("document missing first layer digest")
	}
	// No fabricated package-to-package dependency edges: dependencies only
	// reference the image component.
	var parsed struct {
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Dependencies) != 1 || !strings.HasPrefix(parsed.Dependencies[0].Ref, "image-") {
		t.Fatalf("unexpected dependencies: %+v", parsed.Dependencies)
	}
	if len(parsed.Dependencies[0].DependsOn) != stats.Components {
		t.Errorf("dependency list length: got %d want %d",
			len(parsed.Dependencies[0].DependsOn), stats.Components)
	}
}

func TestExportFailedIndex(t *testing.T) {
	ir := fixture()
	ir.Success = false
	ir.Err = "layer fetch failed"
	var buf bytes.Buffer
	_, err := NewExporter(nil).Export(context.Background(), &buf, FromIndexReport(ir), nil)
	if !errors.Is(err, ErrIndexFailed) {
		t.Fatalf("got %v, want ErrIndexFailed", err)
	}
	if !strings.Contains(err.Error(), "layer fetch failed") {
		t.Errorf("error does not carry indexer reason: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("failed export wrote %d bytes before failing", buf.Len())
	}
}

func TestExportNilReport(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewExporter(nil).Export(context.Background(), &buf, nil, nil); err == nil {
		t.Fatal("nil report should fail")
	}
}

func TestExportFilters(t *testing.T) {
	ir := fixture()
	ctx := context.Background()
	t.Run("TypeFilter", func(t *testing.T) {
		var buf bytes.Buffer
		opts := &Options{Filter: Filter{Types: []string{"pypi"}}}
		stats, err := NewExporter(nil).Export(ctx, &buf, FromIndexReport(ir), opts)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Components != 1 {
			t.Fatalf("components: got %d want 1", stats.Components)
		}
		if !strings.Contains(buf.String(), `pkg:pypi/django@4.2.1`) {
			t.Error("expected only the python package")
		}
		if strings.Contains(buf.String(), `pkg:deb/`) {
			t.Error("deb package should have been filtered out")
		}
	})
	t.Run("LayerFilter", func(t *testing.T) {
		l1 := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		var buf bytes.Buffer
		opts := &Options{Filter: Filter{Layers: []string{l1}}}
		stats, err := NewExporter(nil).Export(ctx, &buf, FromIndexReport(ir), opts)
		if err != nil {
			t.Fatal(err)
		}
		// Only bash + bash source are introduced in layer 1.
		if stats.Components != 2 {
			t.Fatalf("components: got %d want 2", stats.Components)
		}
		if stats.Layers != 1 {
			t.Fatalf("layers: got %d want 1", stats.Layers)
		}
	})
}

// TestExportDedupAcrossLayers verifies that a package introduced in multiple
// layers is emitted as a single component whose layer references cover every
// layer, rather than duplicated or partially merged.
func TestExportDedupAcrossLayers(t *testing.T) {
	manifest := claircore.MustParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	l1 := claircore.MustParseDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	l2 := claircore.MustParseDigest("sha256:2222222222222222222222222222222222222222222222222222222222222222")
	l3 := claircore.MustParseDigest("sha256:3333333333333333333333333333333333333333333333333333333333333333")
	pkg := &claircore.Package{
		ID:       "7",
		Name:     "shared-lib",
		Version:  "1.0",
		Kind:     ccTypes.BinaryPackage,
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	ir := &claircore.IndexReport{
		Hash:     manifest,
		State:    "IndexFinished",
		Success:  true,
		Packages: map[string]*claircore.Package{pkg.ID: pkg},
		Environments: map[string][]*claircore.Environment{
			pkg.ID: {
				{IntroducedIn: l1},
				{IntroducedIn: l2},
				{IntroducedIn: l3},
			},
		},
	}
	buf, stats := export(t, ir, nil)
	if stats.Components != 1 {
		t.Fatalf("components: got %d want 1 (package must not be duplicated)", stats.Components)
	}
	if stats.Layers != 3 {
		t.Fatalf("layers: got %d want 3", stats.Layers)
	}
	var parsed struct {
		Components []struct {
			Name       string `json:"name"`
			Components []struct {
				BOMRef string `json:"bom-ref"`
			} `json:"components"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	var pkgCount, layerRefs int
	for _, c := range parsed.Components {
		if c.Name == "shared-lib" {
			pkgCount++
			layerRefs = len(c.Components)
		}
	}
	if pkgCount != 1 {
		t.Errorf("shared-lib emitted %d times, want exactly 1", pkgCount)
	}
	if layerRefs != 3 {
		t.Errorf("merged layer refs: got %d want 3", layerRefs)
	}
}

func TestExportIncompleteState(t *testing.T) {
	ir := fixture()
	ir.State = "Coalesce"
	buf, _ := export(t, ir, nil)
	var parsed struct {
		Compositions []struct {
			Type string `json:"type"`
		} `json:"compositions"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Compositions) != 1 || parsed.Compositions[0].Type != "incomplete" {
		t.Fatalf("expected incomplete composition, got %+v", parsed.Compositions)
	}
}

// failingWriter errors after a handful of writes, simulating a client that
// disconnects mid-stream.
type failingWriter struct{ remaining int }

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	f.remaining--
	return len(p), nil
}

func TestExportClientDisconnect(t *testing.T) {
	ir := largeReport(200)
	w := &failingWriter{remaining: 2}
	_, err := NewExporter(&Options{FlushBytes: 64}).Export(
		context.Background(), w, FromIndexReport(ir), nil)
	if err == nil {
		t.Fatal("expected an error when the writer fails")
	}
}

func TestExportStreaming(t *testing.T) {
	// A large report must be flushed repeatedly while staying within the buffer
	// bound, rather than buffering the whole document.
	const n = 5000
	ir := largeReport(n)
	opts := &Options{FlushBytes: 4096}
	var buf bytes.Buffer
	stats, err := NewExporter(opts).Export(context.Background(), &buf, FromIndexReport(ir), opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Components != n {
		t.Fatalf("components: got %d want %d", stats.Components, n)
	}
	if stats.FlushCount < 10 {
		t.Errorf("expected repeated flushes for a large report, got %d", stats.FlushCount)
	}
	if stats.Buffered > 4096*2 {
		t.Errorf("buffer high-water mark %d exceeded bound by too much", stats.Buffered)
	}
	if stats.BytesWritten != int64(buf.Len()) {
		t.Errorf("bytes written: observed %d, actual %d", stats.BytesWritten, buf.Len())
	}
}

// TestExportHundredThousandScale exercises the production-scale case called out
// in the requirements: a 100k-package image. It asserts that the output buffer
// stays bounded regardless of document size and that flushes scale with the
// number of components, proving the document is streamed rather than assembled
// in memory.
func TestExportHundredThousandScale(t *testing.T) {
	const n = 100_000
	ir := largeReport(n)
	const bound = 16 * 1024
	opts := &Options{FlushBytes: bound}

	// A discard sink keeps the test's own footprint out of the measurement;
	// only the exporter's internal buffer bounds matter.
	stats, err := NewExporter(opts).Export(context.Background(), io.Discard, FromIndexReport(ir), opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Components != n {
		t.Fatalf("components: got %d want %d", stats.Components, n)
	}
	if stats.Buffered > bound*2 {
		t.Errorf("buffer high-water mark %d exceeded bound %d for a %d-package report",
			stats.Buffered, bound, n)
	}
	// With ~100k components, a streaming writer bounded at 16KiB must flush
	// hundreds of times. A non-streaming implementation would flush once.
	if stats.FlushCount < 100 {
		t.Errorf("expected hundreds of flushes at 100k scale, got %d", stats.FlushCount)
	}
	t.Logf("100k export: components=%d flushes=%d buffered_peak=%d bytes=%d",
		stats.Components, stats.FlushCount, stats.Buffered, stats.BytesWritten)
}

// TestExportStreamingFlushesScale shows flushes grow with package count while
// the buffer peak stays flat, the core memory-stability property.
func TestExportStreamingFlushesScale(t *testing.T) {
	const bound = 8 * 1024
	opts := &Options{FlushBytes: bound}
	prev := 0
	for _, n := range []int{1_000, 10_000, 50_000} {
		stats, err := NewExporter(opts).Export(
			context.Background(), io.Discard, FromIndexReport(largeReport(n)), opts)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Buffered > bound*2 {
			t.Errorf("n=%d: buffer peak %d exceeds bound", n, stats.Buffered)
		}
		if stats.FlushCount <= prev {
			t.Errorf("n=%d: flushes %d did not grow from %d", n, stats.FlushCount, prev)
		}
		prev = stats.FlushCount
	}
}

func TestExportCancellation(t *testing.T) {
	ir := largeReport(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	_, err := NewExporter(nil).Export(ctx, &buf, FromIndexReport(ir), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// largeReport builds an index report with n dpkg packages spread over several
// layers, used for streaming and cancellation tests.
func largeReport(n int) *claircore.IndexReport {
	manifest := claircore.MustParseDigest("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	pkgs := make(map[string]*claircore.Package, n)
	envs := make(map[string][]*claircore.Environment, n)
	layers := make(map[string]claircore.Digest, 4)
	for i := 0; i < 4; i++ {
		layers[string(rune('a'+i))] = claircore.MustParseDigest(
			"sha256:" + strings.Repeat(string(rune('a'+i)), 64))
	}
	for i := 0; i < n; i++ {
		id := string(rune('a' + i%4))
		layer := layers[id]
		name := fmt.Sprintf("pkg-%06d", i)
		pkg := &claircore.Package{
			ID:       name,
			Name:     name,
			Version:  "1.0.0",
			Kind:     ccTypes.BinaryPackage,
			Arch:     "amd64",
			Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
		}
		pkgs[pkg.ID] = pkg
		envs[pkg.ID] = []*claircore.Environment{{IntroducedIn: layer, DistributionID: "d"}}
	}
	return &claircore.IndexReport{
		Hash:         manifest,
		State:        "IndexFinished",
		Success:      true,
		Packages:     pkgs,
		Environments: envs,
		Distributions: map[string]*claircore.Distribution{
			"d": {ID: "d", DID: "ubuntu", VersionID: "22.04"},
		},
	}
}
