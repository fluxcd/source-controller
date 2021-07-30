/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"

type artifactSet []*sourcev1.Artifact

// Diff returns true if any of the revisions in the artifactSet does not match any of the given artifacts.
func (s artifactSet) Diff(set artifactSet) bool {
	if len(s) != len(set) {
		return true
	}

outer:
	for _, j := range s {
		for _, k := range set {
			if k.HasRevision(j.Revision) {
				continue outer
			}
		}
		return true
	}
	return false
}

// hasArtifactUpdated returns true if any of the revisions in the current artifacts
// does not match any of the artifacts in the updated artifacts
// NOTE: artifactSet is a replacement for this. Remove this once it's not used
// anywhere.
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
