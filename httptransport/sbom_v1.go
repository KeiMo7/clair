package httptransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/quay/claircore"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/middleware/compress"
	"github.com/quay/clair/v4/sbom"
)

// NewSBOMV1 returns an http.Handler serving SBOM exports of index reports
// rooted at "prefix".
func NewSBOMV1(_ context.Context, prefix string, srv indexer.Service, topt otelhttp.Option) *SBOMV1 {
	prefix = path.Join("/", prefix) // Ensure the prefix is rooted and cleaned.
	m := http.NewServeMux()
	h := SBOMV1{
		inner: otelhttp.NewHandler(
			compress.Handler(m),
			"sbomv1",
			otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
			topt,
		),
		srv: srv,
	}
	p := path.Join(prefix, "sbom") + "/"
	m.Handle(p, sbomv1wrapper.wrapFunc(p, h.sbomReport))
	return &h
}

// SBOMV1 serves SBOM exports of indexed manifests.
type SBOMV1 struct {
	inner http.Handler
	srv   indexer.Service
}

var _ http.Handler = (*SBOMV1)(nil)

// ServeHTTP implements http.Handler. It applies the same request-ID, response
// recording and structured access logging as the other v1 handlers.
func (h *SBOMV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r = withRequestID(r)
	ctx := r.Context()
	var status int
	var length int64
	w = httputil.ResponseRecorder(&status, &length, w)
	defer func() {
		switch err := http.NewResponseController(w).Flush(); {
		case errors.Is(err, nil):
		case errors.Is(err, http.ErrNotSupported): // Skip
		default:
			slog.WarnContext(ctx, "unable to flush http response",
				"reason", err)
		}
		slog.InfoContext(ctx, "handled HTTP request",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"request_uri", r.RequestURI,
			"status", status,
			"written", length,
			"duration", time.Since(start))
	}()
	h.inner.ServeHTTP(w, r)
}

// allowedSBOMMediaTypes is the content negotiation list for SBOM exports, in
// preference order.
var allowedSBOMMediaTypes = []string{
	sbom.CycloneDXJSONMediaType,
	"application/json",
}

// sbomReport handles GET .../sbom/{digest}, streaming a CycloneDX document for
// the indexed manifest.
func (h *SBOMV1) sbomReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet {
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}
	switch err := pickContentType(w, r, allowedSBOMMediaTypes); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allowedSBOMMediaTypes)
	default:
		apiError(ctx, w, http.StatusBadRequest, "malformed request: %v", err)
	}

	d, err := getDigest(w, r)
	if err != nil {
		apiError(ctx, w, http.StatusBadRequest, "malformed path: %v", err)
	}

	filter, err := parseSBOMFilter(r)
	if err != nil {
		apiError(ctx, w, http.StatusBadRequest, "malformed query: %v", err)
	}

	report, ok, err := h.srv.IndexReport(ctx, d)
	switch {
	case err != nil:
		apiError(ctx, w, http.StatusInternalServerError, "could not retrieve index report: %v", err)
	case !ok:
		// Distinct, explicit status for an unknown manifest.
		apiError(ctx, w, http.StatusNotFound, "index report not found")
	}
	if !report.Success {
		// A failed index must end the export with an error and the recorded
		// reason, never a document that looks complete.
		apiError(ctx, w, http.StatusConflict, "index report unsuccessful: %s", report.Err)
	}

	exporter := sbom.NewExporter(nil)
	// The negotiated content type set by pickContentType is left intact: both
	// acceptable types carry the same CycloneDX JSON body.
	validator := sbomETag(report, filter)
	w.Header().Set("etag", validator)
	if unmodified(r, validator) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	var writeErr error
	defer writerError(w, &writeErr)()
	w.WriteHeader(http.StatusOK)

	stats, err := exporter.Export(ctx, w, sbom.FromIndexReport(report), &sbom.Options{Filter: filter})
	if err != nil {
		// The status line has already been sent, so the failure is surfaced via
		// the Clair-Error trailer (see writerError) and the request log, matching
		// the existing streaming conventions.
		writeErr = err
		slog.WarnContext(ctx, "sbom export failed",
			"manifest", d.String(), "reason", err)
		return
	}
	slog.DebugContext(ctx, "sbom export complete",
		"manifest", d.String(),
		"components", stats.Components,
		"layers", stats.Layers,
		"skipped", stats.Skipped,
		"flushes", stats.FlushCount,
		"bytes", stats.BytesWritten)
}

// sbomETag builds a validator for the exported document from the manifest hash,
// the index state and the active filter. A changed index state or a different
// filter therefore invalidates cached exports, while identical requests share
// a validator. The components are sorted so the value does not depend on query
// parameter order.
func sbomETag(report *claircore.IndexReport, f sbom.Filter) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s", report.Hash.String(), report.State)
	types := append([]string(nil), f.Types...)
	layers := append([]string(nil), f.Layers...)
	sort.Strings(types)
	sort.Strings(layers)
	fmt.Fprintf(h, "\x00types=%v\x00layers=%v", types, layers)
	return `"` + hex.EncodeToString(h.Sum(nil)) + `"`
}

// parseSBOMFilter reads the optional "type" and "layer" query parameters.
//
// "type" may be repeated or comma-separated and selects PURL ecosystem types.
// "layer" may be repeated and selects layer digests in "algo:hex" form.
func parseSBOMFilter(r *http.Request) (sbom.Filter, error) {
	q := r.URL.Query()
	var f sbom.Filter
	for _, v := range q["type"] {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				f.Types = append(f.Types, t)
			}
		}
	}
	for _, v := range q["layer"] {
		for _, l := range strings.Split(v, ",") {
			if l = strings.TrimSpace(l); l != "" {
				if _, err := claircore.ParseDigest(l); err != nil {
					return sbom.Filter{}, err
				}
				f.Layers = append(f.Layers, l)
			}
		}
	}
	return f, nil
}

func init() {
	sbomv1wrapper.init("sbomv1")
}

var sbomv1wrapper wrapper
