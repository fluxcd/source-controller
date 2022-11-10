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

// Package features sets the feature gates that
// source-controller supports, and their default
// states.
package features

import feathelper "github.com/fluxcd/pkg/runtime/features"

const (
	// OptimizedGitClones decreases resource utilization for GitRepository
	// reconciliations. It supports both go-git and libgit2 implementations
	// when cloning repositories using branches or tags.
	//
	// When enabled, avoids full clone operations by first checking whether
	// the last revision is still the same at the target repository,
	// and if that is so, skips the reconciliation.
	OptimizedGitClones = "OptimizedGitClones"
	// ForceGoGitImplementation ignores the value set for gitImplementation
	// and ensures that go-git is used for all GitRepository objects.
	//
	// Libgit2 is built in C and we use the Go bindings provided by git2go
	// to cross the C-GO chasm. Unfortunately, when libgit2 is being used the
	// controllers are known to panic over long periods of time, or when
	// under high GC pressure.
	//
	// This feature gate enables the gradual deprecation of libgit2 in favour
	// of go-git, which so far is the most stable of the pair.
	//
	// When enabled, libgit2 won't be initialized, nor will any git2go CGO
	// code be called.
	ForceGoGitImplementation = "ForceGoGitImplementation"
)

var features = map[string]bool{
	// OptimizedGitClones
	// opt-out from v0.25
	OptimizedGitClones: true,
	// ForceGoGitImplementation
	// opt-out from v0.32
	ForceGoGitImplementation: true,
}

// DefaultFeatureGates contains a list of all supported feature gates and
// their default values.
func FeatureGates() map[string]bool {
	return features
}

// Enabled verifies whether the feature is enabled or not.
//
// This is only a wrapper around the Enabled func in
// pkg/runtime/features, so callers won't need to import
// both packages for checking whether a feature is enabled.
func Enabled(feature string) (bool, error) {
	return feathelper.Enabled(feature)
}

// Disable disables the specified feature. If the feature is not
// present, it's a no-op.
func Disable(feature string) {
	if _, ok := features[feature]; ok {
		features[feature] = false
	}
}
