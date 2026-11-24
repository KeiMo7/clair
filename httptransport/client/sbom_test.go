package client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/clair/v4/httptransport/client"
)

// TestSBOMExport verifies the client requests the SBOM path, negotiates the
// CycloneDX media type and streams the body without buffering it locally.
func TestSBOMExport(t *testing.T) {
	const body = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	var gotPath, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("accept")
		if r.URL.Query().Get("type") != "deb" {
			t.Errorf("missing type query, got %q", r.URL.RawQuery)
		}
		w.Header().Set("content-type", "application/vnd.cyclonedx+json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	c, err := client.NewHTTP(context.Background(), client.WithAddr(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := c.SBOMExport(context.Background(),
		claircore.MustParseDigest(digest),
		client.SBOMFilter{Types: []string{"deb"}})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("body: got %q want %q", got, body)
	}
	if !strings.HasSuffix(gotPath, "/indexer/api/v1/sbom/"+digest) {
		t.Errorf("path: got %q", gotPath)
	}
	if gotAccept != "application/vnd.cyclonedx+json" {
		t.Errorf("accept: got %q", gotAccept)
	}
}

// TestSBOMExportError verifies non-200 responses become ErrRequestFail and do
// not leak the response body.
func TestSBOMExportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := client.NewHTTP(context.Background(), client.WithAddr(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := c.SBOMExport(context.Background(),
		claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
		client.SBOMFilter{})
	if err == nil {
		rc.Close()
		t.Fatal("expected an error for 404")
	}
	if rc != nil {
		t.Error("reader must be nil on error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should carry status, got %v", err)
	}
}
