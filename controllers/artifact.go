package controllers

import sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"

// hasArtifactUpdated returns true if any of the revisions in the current artifacts
// does not match any of the artifacts in the updated artifacts
func hasArtifactUpdated(current []*sourcev1.Artifact, updated []*sourcev1.Artifact) bool {
	if len(current) != len(updated) {
		return true
	}

OUTER:
	for _, c := range current {
		for _, u := range updated {
			if u.HasRevision(c.Revision) {
				continue OUTER
			}
		}
		return true
	}

	return false
}
