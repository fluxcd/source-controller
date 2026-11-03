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
	"os"
	"path/filepath"
	"testing"

	"github.com/fluxcd/pkg/artifact/storage"
)

func TestRemoveArtifactsForMissingObject(t *testing.T) {
	basePath := t.TempDir()
	targetDir := filepath.Join(basePath, storage.ArtifactDir("HelmRepository", "default", "podinfo"))
	otherDir := filepath.Join(basePath, storage.ArtifactDir("HelmRepository", "default", "other"))
	for _, dir := range []string{targetDir, otherDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "artifact.tgz"), []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeArtifactsForMissingObject(&storage.Storage{BasePath: basePath}, "HelmRepository", "default", "podinfo"); err != nil {
		t.Fatalf("removeArtifactsForMissingObject() error = %v", err)
	}
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("expected target artifact directory to be removed, stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(otherDir, "artifact.tgz")); err != nil {
		t.Fatalf("expected unrelated artifact to remain, stat error = %v", err)
	}
}
