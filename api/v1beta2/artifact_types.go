/*
Copyright 2022 The Flux authors

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

package v1beta2

import (
	"path"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Artifact represents the output of a Source reconciliation.
//
// Deprecated: use Artifact from api/v1 instead. This type will be removed in
// a future release.
type Artifact struct {
	// Path is the relative file path of the Artifact. It can be used to locate
	// the file in the root of the Artifact storage on the local file system of
	// the controller managing the Source.
	// +required
	Path string `json:"path"`

	// URL is the HTTP address of the Artifact as exposed by the controller
	// managing the Source. It can be used to retrieve the Artifact for
	// consumption, e.g. by another controller applying the Artifact contents.
	// +required
	URL string `json:"url"`

	// Revision is a human-readable identifier traceable in the origin source
	// system. It can be a Git commit SHA, Git tag, a Helm chart version, etc.
	// +optional
	Revision string `json:"revision"`

	// Checksum is the SHA256 checksum of the Artifact file.
	// Deprecated: use Artifact.Digest instead.
	// +optional
	Checksum string `json:"checksum,omitempty"`

	// Digest is the digest of the file in the form of '<algorithm>:<checksum>'.
	// +optional
	// +kubebuilder:validation:Pattern="^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$"
	Digest string `json:"digest,omitempty"`

	// LastUpdateTime is the timestamp corresponding to the last update of the
	// Artifact.
	// +required
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`

	// Size is the number of bytes in the file.
	// +optional
	Size *int64 `json:"size,omitempty"`

	// Metadata holds upstream information such as OCI annotations.
	// +optional
	Metadata map[string]string `json:"metadata,omitempty"`
}

// HasRevision returns if the given revision matches the current Revision of
// the Artifact.
func (in *Artifact) HasRevision(revision string) bool {
	if in == nil {
		return false
	}
	return TransformLegacyRevision(in.Revision) == TransformLegacyRevision(revision)
}

// HasChecksum returns if the given checksum matches the current Checksum of
// the Artifact.
func (in *Artifact) HasChecksum(checksum string) bool {
	if in == nil {
		return false
	}
	return in.Checksum == checksum
}

// ArtifactDir returns the artifact dir path in the form of
// '<kind>/<namespace>/<name>'.
func ArtifactDir(kind, namespace, name string) string {
	kind = strings.ToLower(kind)
	return path.Join(kind, namespace, name)
}

// ArtifactPath returns the artifact path in the form of
// '<kind>/<namespace>/name>/<filename>'.
func ArtifactPath(kind, namespace, name, filename string) string {
	return path.Join(ArtifactDir(kind, namespace, name), filename)
}

// TransformLegacyRevision transforms a "legacy" revision string into a "new"
// revision string. It accepts the following formats:
//
//   - main/5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - feature/branch/5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - HEAD/5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - tag/55609ff9d959589ed917ce32e6bc0f0a36809565f308602c15c3668965979edc
//   - d52bde83c5b2bd0fa7910264e0afc3ac9cfe9b6636ca29c05c09742f01d5a4bd
//
// Which are transformed into the following formats respectively:
//
//   - main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - feature/branch@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738
//   - tag@sha256:55609ff9d959589ed917ce32e6bc0f0a36809565f308602c15c3668965979edc
//   - sha256:d52bde83c5b2bd0fa7910264e0afc3ac9cfe9b6636ca29c05c09742f01d5a4bd
//
// Deprecated, this function exists for backwards compatibility with existing
// resources, and to provide a transition period. Will be removed in a future
// release.
func TransformLegacyRevision(rev string) string {
	if rev != "" && strings.LastIndex(rev, ":") == -1 {
		if i := strings.LastIndex(rev, "/"); i >= 0 {
			sha := rev[i+1:]
			if algo := determineSHAType(sha); algo != "" {
				if name := rev[:i]; name != "HEAD" {
					return name + "@" + algo + ":" + sha
				}
				return algo + ":" + sha
			}
		}
		if algo := determineSHAType(rev); algo != "" {
			return algo + ":" + rev
		}
	}
	return rev
}

// isAlphaNumHex returns true if the given string only contains 0-9 and a-f
// characters.
var isAlphaNumHex = regexp.MustCompile(`^[0-9a-f]+$`).MatchString

// determineSHAType returns the SHA algorithm used to compute the provided hex.
// The determination is heuristic and based on the length of the hex string. If
// the size is not recognized, an empty string is returned.
func determineSHAType(hex string) string {
	if isAlphaNumHex(hex) {
		switch len(hex) {
		case 40:
			return "sha1"
		case 64:
			return "sha256"
		}
	}
	return ""
}
