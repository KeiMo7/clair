package sbom

import (
	"sort"

	"github.com/quay/claircore"
)

// Report is the subset of a [github.com/quay/claircore.IndexReport] an export
// is based on. It is a thin wrapper that presents the report's lookup maps in
// deterministic order without copying the underlying structures.
type Report struct {
	// Hash is the manifest digest the index report describes.
	Hash claircore.Digest
	// State is the index operation state recorded on the report.
	State string
	// Success reports whether the index operation finished successfully.
	Success bool
	// Err is the error string recorded when Success is false.
	Err string

	pkgs   map[string]*claircore.Package
	dists  map[string]*claircore.Distribution
	repos  map[string]*claircore.Repository
	envs   map[string][]*claircore.Environment
	layers map[string]struct{}
}

// FromIndexReport wraps an index report for export.
//
// No data is copied beyond small identifier slices: the package, distribution
// and repository maps continue to be owned by the index report.
func FromIndexReport(ir *claircore.IndexReport) *Report {
	r := &Report{
		Hash:    ir.Hash,
		State:   ir.State,
		Success: ir.Success,
		Err:     ir.Err,
		pkgs:    ir.Packages,
		dists:   ir.Distributions,
		repos:   ir.Repositories,
		envs:    ir.Environments,
	}
	// Derive the set of layers actually referenced by package environments.
	// The index report itself does not carry a layer list, so environments are
	// the authoritative source of layer information.
	if len(ir.Environments) != 0 {
		r.layers = make(map[string]struct{})
		for _, envs := range ir.Environments {
			for _, env := range envs {
				if s := env.IntroducedIn.String(); s != "" {
					r.layers[s] = struct{}{}
				}
			}
		}
	}
	return r
}

// sortedPackageIDs returns the package map keys in lexicographic order.
//
// Package IDs are assigned by the indexer as numeric strings, but lexicographic
// ordering is used deliberately: the export must not depend on IDs being
// numeric, and lexicographic order is total over arbitrary strings.
func (r *Report) sortedPackageIDs() []string {
	ids := make([]string, 0, len(r.pkgs))
	for id := range r.pkgs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// sortedLayers returns the digests of referenced layers in lexicographic order.
func (r *Report) sortedLayers() []string {
	if len(r.layers) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.layers))
	for d := range r.layers {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// environmentsFor returns the environments recorded for a package ID, sorted
// so that iteration is deterministic. Environments have no natural key, so
// their stable text representation is used as the sort key.
func (r *Report) environmentsFor(id string) []*claircore.Environment {
	envs := r.envs[id]
	sort.SliceStable(envs, func(i, j int) bool {
		return envKey(envs[i]) < envKey(envs[j])
	})
	return envs
}

// envKey produces a stable comparison key for an environment.
func envKey(e *claircore.Environment) string {
	// IntroducedIn digest, package database and distribution/repository IDs
	// fully distinguish environments in an index report.
	key := e.IntroducedIn.String() + "\x00" + e.PackageDB + "\x00" + e.DistributionID + "\x00"
	ids := append([]string(nil), e.RepositoryIDs...)
	sort.Strings(ids)
	for _, id := range ids {
		key += id + ","
	}
	return key
}
