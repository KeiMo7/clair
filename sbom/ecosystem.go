package sbom

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	ccTypes "github.com/quay/claircore/toolkit/types"
)

// ecosystem describes how packages discovered by a particular Clair detector
// are represented in the exported document.
type ecosystem struct {
	// purlType is the Package URL "type" component, per the PURL specification's
	// ecosystem conventions.
	purlType string
	// cdxType is the CycloneDX component type used for the ecosystem's packages.
	cdxType componentType
	// distro marks operating-system distribution package managers. Language
	// package managers set this false.
	distro bool
	// namespace reports whether PURLs of this ecosystem carry a namespace.
	namespace bool
}

// componentType mirrors the CycloneDX component type vocabulary. Only the
// values emitted by this package are listed.
type componentType string

const (
	componentLibrary   componentType = "library"
	componentOperating componentType = "operating-system"
)

// detectorEcosystems maps Clair package detector names to their ecosystems.
//
// Detector names are the values returned by package scanners' Name method (for
// example the dpkg scanner reports "dpkg"). Distribution package managers and
// language package managers use distinct PURL types, as required by the PURL
// specification.
var detectorEcosystems = map[string]ecosystem{
	// Distribution packages.
	"dpkg": {purlType: "deb", cdxType: componentOperating, distro: true},
	"apk":  {purlType: "apk", cdxType: componentOperating, distro: true},
	"rpm":  {purlType: "rpm", cdxType: componentOperating, distro: true},
	// Language packages.
	"python": {purlType: "pypi", cdxType: componentLibrary},
	"java":   {purlType: "maven", cdxType: componentLibrary, namespace: true},
	"gobin":  {purlType: "golang", cdxType: componentLibrary},
	"ruby":   {purlType: "gem", cdxType: componentLibrary},
	"nodejs": {purlType: "npm", cdxType: componentLibrary},
}

// unknownEcosystem is used when a package's detector is not recognized. Such
// packages are skipped by the export and counted as malformed, rather than
// emitted with an invented type.
var unknownEcosystem = ecosystem{}

// ecosystemFor resolves the ecosystem a package was discovered in. It returns
// false when the package carries no detector or the detector is not known.
func ecosystemFor(p *claircore.Package) (ecosystem, bool) {
	if p.Detector == nil || p.Detector.Name == "" {
		return unknownEcosystem, false
	}
	eco, ok := detectorEcosystems[p.Detector.Name]
	return eco, ok
}

// makePURL builds the canonical Package URL for a package in its ecosystem.
//
// Distribution and language packages use different PURL types and namespaces:
// Maven coordinates split "group:artifact" into namespace/name, while the other
// ecosystems keep an empty namespace. Distribution PURLs carry an "arch"
// qualifier when the package records one and a "distro" qualifier when a
// distribution context is known.
func makePURL(eco ecosystem, p *claircore.Package, dist *claircore.Distribution) (packageurl.PackageURL, error) {
	name := p.Name
	namespace := ""
	switch eco.purlType {
	case "maven":
		// Clair stores Maven coordinates as "group:artifact" in Name. The PURL
		// convention puts the group in the namespace and the artifact in name.
		group, artifact, found := strings.Cut(name, ":")
		if !found || group == "" || artifact == "" {
			return packageurl.PackageURL{}, fmt.Errorf("sbom: malformed maven coordinate %q", name)
		}
		namespace, name = group, artifact
	}
	qual := packageurl.Qualifiers{}
	if eco.distro && p.Arch != "" {
		qual = append(qual, packageurl.Qualifier{Key: "arch", Value: p.Arch})
	}
	if eco.distro && dist != nil && dist.DID != "" && dist.VersionID != "" {
		qual = append(qual, packageurl.Qualifier{
			Key:   "distro",
			Value: dist.DID + "-" + dist.VersionID,
		})
	}
	purl := packageurl.PackageURL{
		Type:       eco.purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    p.Version,
		Qualifiers: qual,
	}
	return purl, nil
}

// isSourcePackage reports whether the package is a source package rather than
// an installed binary. Source packages are emitted with a CycloneDX property
// recording the kind.
func isSourcePackage(p *claircore.Package) bool {
	return p.Kind == ccTypes.SourcePackage
}
