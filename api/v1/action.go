/*
Copyright 2026 The Flux authors

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

package v1

// Action describes an observable stage of a source reconcile loop, from
// reconciling the local artifact storage through acquiring and verifying the
// upstream source, packaging the artifact and finalizing on deletion.
type Action string

// String returns the string representation of the Action.
func (a Action) String() string {
	return string(a)
}

const (
	// ActionReconcile denotes the overall outcome of the reconcile loop,
	// emitted once per run to report that reconciliation finished or failed.
	ActionReconcile Action = "Reconcile"

	// ActionReconcileStorage verifies that the advertised artifact still
	// exists in local storage, reconstructs the storage path, garbage
	// collects stale artifacts and sets the artifact URL.
	ActionReconcileStorage Action = "ReconcileStorage"

	// ActionReconcileSource acquires the upstream content — cloning the Git
	// repository, pulling the OCI artifact, downloading the Helm index or
	// chart, or fetching the Bucket objects — into a working directory and
	// determines the revision.
	ActionReconcileSource Action = "ReconcileSource"

	// ActionVerifySource validates the authenticity of the acquired source,
	// using PGP or SSH for GitRepository and Cosign or Notation for
	// OCIRepository and HelmChart. It runs as part of ReconcileSource.
	ActionVerifySource Action = "VerifySource"

	// ActionReconcileArtifact archives the acquired content into an immutable
	// Artifact, persists it under the per-object storage lock and publishes
	// the artifact URL and revision.
	ActionReconcileArtifact Action = "ReconcileArtifact"

	// ActionGarbageCollect prunes stale artifacts from storage, honoring the
	// configured retention TTL and record count.
	ActionGarbageCollect Action = "GarbageCollect"

	// ActionFinalize garbage collects the object's artifacts and removes the
	// finalizer when the source is deleted.
	ActionFinalize Action = "Finalize"
)
