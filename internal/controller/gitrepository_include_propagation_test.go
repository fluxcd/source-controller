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
	"time"

	gogit "github.com/go-git/go-git/v5"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// TestGitRepositoryIncludePropagation exercises the manager watch, checkout,
// composition and artifact publication through two include edges.
func TestGitRepositoryIncludePropagation(t *testing.T) {
	g := NewWithT(t)
	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() { g.Expect(os.RemoveAll(server.Root())).To(Succeed()) })
	server.AutoCreate()
	g.Expect(server.StartHTTP()).To(Succeed())
	t.Cleanup(server.StopHTTP)

	leafDir, mainDir := t.TempDir(), t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(leafDir, "value.txt"), []byte("before"), 0o644)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(mainDir, "root.txt"), []byte("unchanged"), 0o644)).To(Succeed())
	leafGit, err := initGitRepo(server, leafDir, git.DefaultBranch, "/leaf.git")
	g.Expect(err).NotTo(HaveOccurred())
	_, err = initGitRepo(server, mainDir, git.DefaultBranch, "/main.git")
	g.Expect(err).NotTo(HaveOccurred())

	newSource := func(path string, include *sourcev1.GitRepository) *sourcev1.GitRepository {
		repo := &sourcev1.GitRepository{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "include-chain-", Namespace: "default"},
			Spec: sourcev1.GitRepositorySpec{
				URL:      server.HTTPAddress() + path,
				Interval: metav1.Duration{Duration: time.Hour},
			},
		}
		if include != nil {
			repo.Spec.Include = []sourcev1.GitRepositoryInclude{{GitRepositoryRef: meta.LocalObjectReference{Name: include.Name}, ToPath: "included"}}
		}
		g.Expect(k8sClient.Create(ctx, repo)).To(Succeed())
		t.Cleanup(func() { g.Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, repo))).To(Succeed()) })
		g.Eventually(func() bool {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(repo), repo); err != nil {
				return false
			}
			return conditions.IsReady(repo) && repo.GetArtifact() != nil
		}, 30*time.Second, 100*time.Millisecond).Should(BeTrue())
		return repo
	}
	leaf := newSource("/leaf.git", nil)
	middle := newSource("/main.git", leaf)
	outer := newSource("/main.git", middle)
	middleBefore, outerBefore := middle.Status.Artifact.DeepCopy(), outer.Status.Artifact.DeepCopy()

	// Only the leaf's Git revision changes. The other objects have hour-long
	// intervals, so their updates must arrive via the include watches.
	g.Expect(os.WriteFile(filepath.Join(leafDir, "value.txt"), []byte("after"), 0o644)).To(Succeed())
	g.Expect(commitFromFixture(leafGit, leafDir)).To(Succeed())
	g.Expect(leafGit.Push(&gogit.PushOptions{})).To(Succeed())
	g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(leaf), leaf)).To(Succeed())
	leaf.Annotations = map[string]string{meta.ReconcileRequestAnnotation: "leaf-update"}
	g.Expect(k8sClient.Update(ctx, leaf)).To(Succeed())
	for _, obj := range []*sourcev1.GitRepository{middle, outer} {
		before := middleBefore
		if obj == outer {
			before = outerBefore
		}
		g.Eventually(func() bool {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				return false
			}
			return conditions.IsReady(obj) && obj.GetArtifact() != nil && obj.GetArtifact().Digest != before.Digest
		}, 30*time.Second, 100*time.Millisecond).Should(BeTrue())
		g.Expect(obj.Status.Artifact.Revision).To(Equal(before.Revision))
	}
	g.Expect(middle.Status.IncludedArtifacts[0].Digest).NotTo(BeEmpty())
	g.Expect(outer.Status.IncludedArtifacts[0].Digest).To(Equal(middle.Status.Artifact.Digest))
	extracted := filepath.Join(t.TempDir(), "artifact")
	g.Expect(testStorage.CopyToPath(outer.Status.Artifact, ".", extracted)).To(Succeed())
	content, err := os.ReadFile(filepath.Join(extracted, "included", "included", "value.txt"))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(string(content)).To(Equal("after"))

	// A forced no-op reconciliation keeps the artifact stable.
	before := outer.Status.Artifact.DeepCopy()
	outer.Annotations = map[string]string{meta.ReconcileRequestAnnotation: "no-op"}
	g.Expect(k8sClient.Update(ctx, outer)).To(Succeed())
	g.Eventually(func() string {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(outer), outer)).To(Succeed())
		return outer.Status.LastHandledReconcileAt
	}, 30*time.Second, 100*time.Millisecond).Should(Equal("no-op"))
	g.Expect(outer.Status.Artifact).To(Equal(before))

	// Timestamp-only source events do not requeue either dependent.
	middleVersion, outerVersion := middle.ResourceVersion, outer.ResourceVersion
	g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(leaf), leaf)).To(Succeed())
	leaf.Status.Artifact.LastUpdateTime = metav1.Now()
	g.Expect(k8sClient.Status().Update(ctx, leaf)).To(Succeed())
	g.Consistently(func() []string {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(middle), middle)).To(Succeed())
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(outer), outer)).To(Succeed())
		return []string{middle.ResourceVersion, outer.ResourceVersion}
	}, time.Second, 100*time.Millisecond).Should(Equal([]string{middleVersion, outerVersion}))
}

func TestGitRepositoryIncludeArchiveStability(t *testing.T) {
	g := NewWithT(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "value")
	g.Expect(os.WriteFile(file, []byte("unchanged"), 0o644)).To(Succeed())
	obj := &sourcev1.GitRepository{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "archive-stability"}}
	artifact := testStorage.NewArtifactFor(sourcev1.GitRepositoryKind, obj, "same", "test.tar.gz")
	g.Expect(testStorage.MkdirAll(artifact)).To(Succeed())
	t.Cleanup(func() { _, err := testStorage.RemoveAll(artifact); g.Expect(err).NotTo(HaveOccurred()) })
	g.Expect(testStorage.Archive(&artifact, dir, nil)).To(Succeed())
	digest := artifact.Digest
	g.Expect(os.Chtimes(file, time.Unix(1000, 0), time.Unix(1000, 0))).To(Succeed())
	g.Expect(testStorage.Archive(&artifact, dir, nil)).To(Succeed())
	g.Expect(artifact.Digest).To(Equal(digest))
}
