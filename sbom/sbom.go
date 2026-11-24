// Package sbom exports software bills of materials derived from Clair
// [github.com/quay/claircore.IndexReport]s.
//
// The package does no storage or scanning of its own: an IndexReport is the
// only input. All output is generated deterministically and streamed, so that
// reports describing very large images never have to be fully materialized in
// memory.
package sbom

import (
	"context"
	"errors"
	"io"
)

// Media type and file format constants.
const (
	// CycloneDXJSONMediaType is the media type of the CycloneDX JSON documents
	// produced by this package, per the CycloneDX specification.
	CycloneDXJSONMediaType = "application/vnd.cyclonedx+json"
	// SpecVersion is the CycloneDX specification version emitted.
	SpecVersion = "1.6"
)

// Filter narrows the set of packages included in an exported document.
//
// The zero value includes every well-formed package in the index report.
type Filter struct {
	// Types restricts the export to packages whose PURL ecosystem type is in
	// the list (for example "deb", "rpm", "pypi", "maven"). When empty, all
	// ecosystem types are included.
	Types []string
	// Layers restricts the export to packages that were introduced in one of
	// the listed layer digests, in the same "algo:hex" string form used by the
	// index report. When empty, all layers are considered.
	Layers []string
}

// Stats summarizes an export run.
type Stats struct {
	// Components is the number of package components written to the document.
	Components int
	// Skipped is the number of packages skipped because a required field was
	// missing. Skipped packages do not fail the export.
	Skipped int
	// Layers is the number of layer components written to the document.
	Layers int
	// FlushCount is the number of times the export flushed its buffered output
	// to the underlying writer. It exists to make the streaming behavior
	// observable: a streaming export of a large report flushes repeatedly
	// rather than buffering the whole document.
	FlushCount int
	// Buffered is the high-water mark, in bytes, of output buffered between
	// flushes during the export.
	Buffered int64
	// BytesWritten is the total number of bytes handed to the underlying
	// writer.
	BytesWritten int64
}

// Options configures an export.
type Options struct {
	// Filter selects the packages and layers to include.
	Filter Filter
	// FlushBytes bounds the amount of encoded output buffered before it is
	// flushed to the underlying writer. When zero, a package-internal default
	// is used. The bounds apply between components: a single component larger
	// than the limit is written in one piece.
	FlushBytes int
}

// ErrIndexFailed is returned when an index report is marked as unsuccessful.
// The wrapped message details the reason recorded by the indexer.
var ErrIndexFailed = errors.New("sbom: index report marked as failed")

// Exporter renders IndexReports as SBOM documents.
//
// An Exporter is safe for concurrent use.
type Exporter struct {
	flushBytes int
}

// NewExporter returns an Exporter using the provided options.
func NewExporter(opts *Options) *Exporter {
	e := &Exporter{flushBytes: defaultFlushBytes}
	if opts != nil && opts.FlushBytes > 0 {
		e.flushBytes = opts.FlushBytes
	}
	return e
}

// Export writes a CycloneDX JSON document describing ir to w.
//
// Export fails without writing a document when the report is unknown or marked
// as failed. Individual packages missing a required field (name, version or a
// recognizable ecosystem) are skipped and counted in the returned [Stats],
// rather than failing the whole export.
//
// The document is encoded and flushed incrementally: packages are sorted and
// emitted one at a time, and the in-memory buffer never grows beyond the
// configured flush bound. If ctx is canceled, for example because the client
// went away, Export stops and returns the context error.
func (e *Exporter) Export(ctx context.Context, w io.Writer, ir *Report, opts *Options) (Stats, error) {
	if ir == nil {
		return Stats{}, errors.New("sbom: nil index report")
	}
	if !ir.Success {
		return Stats{}, errors.Join(ErrIndexFailed, errors.New(ir.Err))
	}
	return e.exportCycloneDX(ctx, w, ir, opts)
}
