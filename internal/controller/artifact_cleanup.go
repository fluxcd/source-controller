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

package controller

import (
	"fmt"
	"os"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/artifact/storage"
)

// removeArtifactsForMissingObject removes artifacts stored by this controller
// for an object that is no longer visible to its cache. This also handles
// objects that moved outside the controller's watch-label selector: they still
// exist in the API, but this shard must stop serving their stale artifacts.
func removeArtifactsForMissingObject(s *storage.Storage, kind, namespace, name string) error {
	if s == nil {
		return nil
	}

	artifactDir, err := securejoin.SecureJoin(s.BasePath, storage.ArtifactDir(kind, namespace, name))
	if err != nil {
		return fmt.Errorf("failed to resolve artifact directory for %s %s/%s: %w", kind, namespace, name, err)
	}
	if err := os.RemoveAll(artifactDir); err != nil {
		return fmt.Errorf("failed to remove artifacts for %s %s/%s: %w", kind, namespace, name, err)
	}
	return nil
}
