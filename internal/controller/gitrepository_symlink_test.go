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
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
)

// treeEntry is a file, or a symlink when link is set.
type treeEntry struct {
	content string
	link    string
}

func TestGitRepositoryReconciler_reconcileSource_commitRemovesSymlink(t *testing.T) {
	tests := []struct {
		name   string
		head   map[string]treeEntry
		commit map[string]treeEntry
	}{
		{
			// https://github.com/fluxcd/source-controller/issues/1921
			name: "symlink deleted, target kept",
			head: map[string]treeEntry{
				"target.txt": {content: "target"},
				"link.txt":   {link: "target.txt"},
			},
			commit: map[string]treeEntry{
				"target.txt": {content: "target"},
			},
		},
		{
			name: "symlink replaced by file whose target is deleted",
			head: map[string]treeEntry{
				"deploy/_stacks/config.yaml": {content: "v2"},
				"deploy/app/config.yaml":     {link: "../_stacks/config.yaml"},
			},
			commit: map[string]treeEntry{
				"deploy/app/config.yaml": {content: "v1"},
			},
		},
		{
			name: "symlink to .git/config deleted",
			head: map[string]treeEntry{
				"app.yaml": {content: "app"},
				"git.yaml": {link: ".git/config"},
			},
			commit: map[string]treeEntry{
				"app.yaml": {content: "app"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server, err := gittestserver.NewTempGitServer()
			g.Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(server.Root())
			g.Expect(server.InitRepo("testdata/git/repository", git.DefaultBranch, "test.git")).To(Succeed())
			g.Expect(server.StartHTTP()).To(Succeed())
			defer server.StopHTTP()

			remote, err := gogit.PlainOpen(filepath.Join(server.Root(), "test.git"))
			g.Expect(err).NotTo(HaveOccurred())
			setBranch(g, remote.Storer, git.DefaultBranch, tt.head)
			commit := setBranch(g, remote.Storer, "commit", tt.commit)

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "symlink-",
					Generation:   1,
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: timeout},
					URL:       server.HTTPAddress() + "/test.git",
					Reference: &sourcev1.GitRepositoryRef{Commit: commit.String()},
				},
			}

			r := &GitRepositoryReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.GitRepository{}).
					Build(),
				Recorder:     events.NewFakeRecorder(32, false),
				Storage:      testStorage,
				patchOptions: getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}
			g.Expect(r.Client.Create(context.TODO(), obj)).To(Succeed())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).To(Succeed())
			}()

			dir := t.TempDir()
			var c git.Commit
			var includes artifactSet
			sp := patch.NewSerialPatcher(obj, r.Client)
			got, err := r.reconcileSource(context.TODO(), sp, obj, &c, &includes, dir)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got).To(Equal(sreconcile.ResultSuccess))
			g.Expect(c.Hash.String()).To(Equal(commit.String()))

			dir, err = filepath.EvalSymlinks(dir)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(filepath.Join(dir, ".git", "config")).To(BeARegularFile())
			g.Expect(readTree(g, dir)).To(Equal(tt.commit))
		})
	}
}

func readTree(g *WithT, dir string) map[string]treeEntry {
	got := map[string]treeEntry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			got[filepath.ToSlash(rel)] = treeEntry{link: target}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = treeEntry{content: string(b)}
		return nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	return got
}

func setBranch(g *WithT, st storer.Storer, branch string, tree map[string]treeEntry) plumbing.Hash {
	sig := object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	commit := &object.Commit{Author: sig, Committer: sig, Message: branch, TreeHash: writeTree(g, st, tree)}
	obj := st.NewEncodedObject()
	g.Expect(commit.Encode(obj)).To(Succeed())
	hash, err := st.SetEncodedObject(obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(st.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), hash))).To(Succeed())
	return hash
}

func writeTree(g *WithT, st storer.Storer, tree map[string]treeEntry) plumbing.Hash {
	subtrees := map[string]map[string]treeEntry{}
	var entries []object.TreeEntry
	for p, e := range tree {
		if dir, rest, ok := strings.Cut(p, "/"); ok {
			if subtrees[dir] == nil {
				subtrees[dir] = map[string]treeEntry{}
			}
			subtrees[dir][rest] = e
			continue
		}
		mode, data := filemode.Regular, e.content
		if e.link != "" {
			mode, data = filemode.Symlink, e.link
		}
		obj := st.NewEncodedObject()
		obj.SetType(plumbing.BlobObject)
		w, err := obj.Writer()
		g.Expect(err).NotTo(HaveOccurred())
		_, err = w.Write([]byte(data))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(w.Close()).To(Succeed())
		hash, err := st.SetEncodedObject(obj)
		g.Expect(err).NotTo(HaveOccurred())
		entries = append(entries, object.TreeEntry{Name: p, Mode: mode, Hash: hash})
	}
	for dir, sub := range subtrees {
		entries = append(entries, object.TreeEntry{Name: dir, Mode: filemode.Dir, Hash: writeTree(g, st, sub)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	obj := st.NewEncodedObject()
	g.Expect((&object.Tree{Entries: entries}).Encode(obj)).To(Succeed())
	hash, err := st.SetEncodedObject(obj)
	g.Expect(err).NotTo(HaveOccurred())
	return hash
}
