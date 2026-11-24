package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	ccTypes "github.com/quay/claircore/toolkit/types"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
)

const sbomDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// sbomFixture is the index report returned by the mock service. It covers a
// well-formed package and one missing a required field.
func sbomFixture() *claircore.IndexReport {
	digest := claircore.MustParseDigest(sbomDigest)
	layer := claircore.MustParseDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	good := &claircore.Package{
		ID:       "1",
		Name:     "bash",
		Version:  "5.1",
		Kind:     ccTypes.BinaryPackage,
		Arch:     "amd64",
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	bad := &claircore.Package{
		ID:       "2",
		Name:     "no-version",
		Detector: &claircore.Detector{Name: "dpkg", Version: "1", Kind: "package"},
	}
	return &claircore.IndexReport{
		Hash:    digest,
		State:   "IndexFinished",
		Success: true,
		Packages: map[string]*claircore.Package{
			good.ID: good, bad.ID: bad,
		},
		Environments: map[string][]*claircore.Environment{
			good.ID: {{IntroducedIn: layer}},
			bad.ID:  {{IntroducedIn: layer}},
		},
	}
}

func newSBOMServer(t *testing.T, report *claircore.IndexReport, found bool, indexErr error) *httptest.Server {
	t.Helper()
	ctx := test.Logging(t)
	i := &indexer.Mock{
		IndexReport_: func(_ context.Context, d claircore.Digest) (*claircore.IndexReport, bool, error) {
			return report, found, indexErr
		},
	}
	v1 := NewSBOMV1(ctx, "", i, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	return srv
}

func TestSBOMExportOK(t *testing.T) {
	report := sbomFixture()
	srv := newSBOMServer(t, report, true, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status: got %d want %d, body: %s", got, want, body)
	}
	if got := res.Header.Get("content-type"); got != "application/vnd.cyclonedx+json" {
		t.Errorf("content-type: got %q", got)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(body), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("invalid CycloneDX: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("no components")
	}
	// One layer + one valid package; the package missing a version is skipped.
	if got, want := len(*bom.Components), 2; got != want {
		t.Errorf("components: got %d want %d", got, want)
	}
}

func TestSBOMExportDeterministic(t *testing.T) {
	report := sbomFixture()
	srv := newSBOMServer(t, report, true, nil)
	defer srv.Close()

	get := func() []byte {
		req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
			srv.URL+"/sbom/"+sbomDigest, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first, second := get(), get()
	if !bytes.Equal(first, second) {
		t.Fatal("two exports of the same index report are not byte-identical")
	}
}

func TestSBOMExportNotFound(t *testing.T) {
	srv := newSBOMServer(t, nil, false, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusNotFound; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}
	var envelope struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(res.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != "not-found" {
		t.Errorf("error code: got %q want not-found", envelope.Code)
	}
}

func TestSBOMExportIndexFailed(t *testing.T) {
	report := sbomFixture()
	report.Success = false
	report.Err = "coalesce failure"
	srv := newSBOMServer(t, report, true, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusConflict; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}
	body, _ := io.ReadAll(res.Body)
	if !bytes.Contains(body, []byte("coalesce failure")) {
		t.Errorf("response does not carry index failure reason: %s", body)
	}
}

func TestSBOMExportMethodNotAllowed(t *testing.T) {
	srv := newSBOMServer(t, sbomFixture(), true, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusMethodNotAllowed; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}
}

func TestSBOMExportTypeFilter(t *testing.T) {
	report := sbomFixture()
	srv := newSBOMServer(t, report, true, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest+"?type=pypi", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(body), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatal(err)
	}
	// Only the layer component remains; the deb package is filtered out.
	if got, want := len(*bom.Components), 1; got != want {
		t.Errorf("components: got %d want %d", got, want)
	}
}

func TestSBOMExportBadLayerFilter(t *testing.T) {
	srv := newSBOMServer(t, sbomFixture(), true, nil)
	defer srv.Close()

	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest+"?layer=not-a-digest", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusBadRequest; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}
}

func TestSBOMExportContentTypeNegotiation(t *testing.T) {
	srv := newSBOMServer(t, sbomFixture(), true, nil)
	defer srv.Close()

	t.Run("VendorType", func(t *testing.T) {
		req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
			srv.URL+"/sbom/"+sbomDigest, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/vnd.cyclonedx+json")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status: %d", res.StatusCode)
		}
		if got := res.Header.Get("content-type"); got != "application/vnd.cyclonedx+json" {
			t.Errorf("content-type: got %q", got)
		}
	})
	t.Run("Unsupported", func(t *testing.T) {
		req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
			srv.URL+"/sbom/"+sbomDigest, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/xml")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if got, want := res.StatusCode, http.StatusUnsupportedMediaType; got != want {
			t.Fatalf("status: got %d want %d", got, want)
		}
	})
}

func TestSBOMExportConditional(t *testing.T) {
	srv := newSBOMServer(t, sbomFixture(), true, nil)
	defer srv.Close()

	// First request obtains the validator.
	req, err := httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	etag := res.Header.Get("etag")
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if etag == "" {
		t.Fatal("no etag returned")
	}

	// Second request with the validator returns 304 and no body.
	req, err = httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("if-none-match", etag)
	res, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusNotModified; got != want {
		t.Fatalf("status: got %d want %d", got, want)
	}
	b, _ := io.ReadAll(res.Body)
	if len(b) != 0 {
		t.Errorf("304 response must have no body, got %d bytes", len(b))
	}

	// A different filter yields a different validator, so the cached one no
	// longer matches.
	req, err = httputil.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/sbom/"+sbomDigest+"?type=deb", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("if-none-match", etag)
	res, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status: got %d want %d (filter must change the validator)", got, want)
	}
}
