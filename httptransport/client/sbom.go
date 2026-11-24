package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/quay/claircore"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/sbom"
)

// SBOMFilter mirrors the server-side export filter.
type SBOMFilter struct {
	// Types selects PURL ecosystem types to include.
	Types []string
	// Layers selects layer digests whose introduced packages are included.
	Layers []claircore.Digest
}

// SBOMExport requests a CycloneDX SBOM for the named manifest and streams the
// document to the returned [io.ReadCloser].
//
// The caller must close the reader. Nothing is buffered beyond what the
// underlying HTTP client does, so exports of large images stream end to end.
//
// A missing manifest reports [http.StatusNotFound]; a failed index reports
// [http.StatusConflict]. Both are returned as [*clairerror.ErrRequestFail].
func (s *HTTP) SBOMExport(ctx context.Context, manifest claircore.Digest, f SBOMFilter) (io.ReadCloser, error) {
	u, err := s.addr.Parse(path.Join(httptransport.SBOMPath, manifest.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse api address: %v", err)
	}
	q := url.Values{}
	for _, t := range f.Types {
		q.Add("type", t)
	}
	for _, l := range f.Layers {
		q.Add("layer", l.String())
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}

	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %v", err)
	}
	req.Header.Set("accept", sbom.CycloneDXJSONMediaType)

	resp, err := s.c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, &clairerror.ErrRequestFail{
			Code:   resp.StatusCode,
			Status: resp.Status,
		}
	}
	return resp.Body, nil
}
