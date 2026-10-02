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

package util

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

func TestPrepareTempRoot(t *testing.T) {
	t.Run("creates the root when it does not exist", func(t *testing.T) {
		g := NewWithT(t)
		root := filepath.Join(t.TempDir(), "source-controller")

		stale, err := PrepareTempRoot(root)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(stale).To(BeEmpty())
		g.Expect(root).To(BeADirectory())
	})

	t.Run("moves a previous process's leftovers out of the root", func(t *testing.T) {
		g := NewWithT(t)
		root := filepath.Join(t.TempDir(), "source-controller")
		leftover := filepath.Join(root, "gitrepository-default-foo-123", "repo")
		g.Expect(os.MkdirAll(leftover, 0o700)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(root, "chart-index-1.yaml"), []byte("x"), 0o600)).To(Succeed())

		stale, err := PrepareTempRoot(root)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(stale).To(HaveLen(1))
		g.Expect(filepath.Join(stale[0], "gitrepository-default-foo-123", "repo")).To(BeADirectory())
		g.Expect(filepath.Join(stale[0], "chart-index-1.yaml")).To(BeARegularFile())

		entries, err := os.ReadDir(root)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(entries).To(BeEmpty())
	})

	t.Run("lists leftovers a previous purge did not finish", func(t *testing.T) {
		g := NewWithT(t)
		parent := t.TempDir()
		root := filepath.Join(parent, "source-controller")
		unfinished := filepath.Join(parent, "source-controller"+staleSuffix+"1")
		unrelated := filepath.Join(parent, "other-controller"+staleSuffix+"1")
		for _, dir := range []string{root, unfinished, unrelated} {
			g.Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
		}

		stale, err := PrepareTempRoot(root)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(stale).To(ContainElement(unfinished))
		g.Expect(stale).ToNot(ContainElement(unrelated))
		g.Expect(stale).To(HaveLen(2))
	})
}

func TestPurgeTempRoots(t *testing.T) {
	t.Run("removes every path", func(t *testing.T) {
		g := NewWithT(t)
		parent := t.TempDir()
		a := filepath.Join(parent, "a", "nested")
		b := filepath.Join(parent, "b")
		g.Expect(os.MkdirAll(a, 0o700)).To(Succeed())
		g.Expect(os.MkdirAll(b, 0o700)).To(Succeed())

		purged := PurgeTempRoots(context.Background(), logr.Discard(), []string{filepath.Join(parent, "a"), b})
		g.Expect(purged).To(Equal(2))
		g.Expect(filepath.Join(parent, "a")).ToNot(BeADirectory())
		g.Expect(b).ToNot(BeADirectory())
	})

	t.Run("stops when the context is done", func(t *testing.T) {
		g := NewWithT(t)
		dir := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		purged := PurgeTempRoots(ctx, logr.Discard(), []string{dir})
		g.Expect(purged).To(Equal(0))
		g.Expect(dir).To(BeADirectory())
	})
}
