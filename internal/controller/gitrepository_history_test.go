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
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/memory"
	. "github.com/onsi/gomega"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// storeCommit stores a commit object with the given parents and returns its
// hash. The tree is irrelevant for history traversal and left empty.
func storeCommit(t *testing.T, s storer.EncodedObjectStorer, message string, parents ...plumbing.Hash) plumbing.Hash {
	t.Helper()
	sig := object.Signature{Name: "Jane Doe", Email: "jane@example.com", When: time.Unix(0, 0)}
	o := s.NewEncodedObject()
	if err := (&object.Commit{Author: sig, Committer: sig, Message: message, ParentHashes: parents}).Encode(o); err != nil {
		t.Fatal(err)
	}
	h, err := s.SetEncodedObject(o)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func Test_findAncestor(t *testing.T) {
	s := memory.NewStorage()

	// a <- b <- c <- d, with side branch a <- s1 merged into m(d, s1).
	a := storeCommit(t, s, "a")
	b := storeCommit(t, s, "b", a)
	c := storeCommit(t, s, "c", b)
	d := storeCommit(t, s, "d", c)
	s1 := storeCommit(t, s, "s1", a)
	m := storeCommit(t, s, "m", d, s1)
	// orphan has a parent that is not in the store.
	orphan := storeCommit(t, s, "orphan", plumbing.NewHash("0123456789012345678901234567890123456789"))

	tests := []struct {
		name     string
		shallow  []plumbing.Hash
		head     plumbing.Hash
		ancestor plumbing.Hash
		limit    int
		want     ancestryResult
	}{
		{name: "same commit", head: d, ancestor: d, limit: 1, want: ancestryFound},
		{name: "linear ancestor", head: d, ancestor: a, limit: 10, want: ancestryFound},
		{name: "linear descendant is not an ancestor", head: a, ancestor: d, limit: 10, want: ancestryNotFound},
		{name: "unrelated commit", head: d, ancestor: s1, limit: 10, want: ancestryNotFound},
		{name: "ancestor through the first parent of a merge", head: m, ancestor: c, limit: 10, want: ancestryFound},
		{name: "ancestor through the second parent of a merge", head: m, ancestor: s1, limit: 10, want: ancestryFound},
		{name: "shallow boundary before the ancestor", shallow: []plumbing.Hash{b}, head: d, ancestor: a, limit: 10, want: ancestryTruncated},
		{name: "shallow boundary is the ancestor", shallow: []plumbing.Hash{b}, head: d, ancestor: b, limit: 10, want: ancestryFound},
		{name: "shallow boundary on one parent chain of a merge", shallow: []plumbing.Hash{c}, head: m, ancestor: s1, limit: 10, want: ancestryFound},
		{name: "shallow boundary on both parent chains of a merge", shallow: []plumbing.Hash{c, s1}, head: m, ancestor: a, limit: 10, want: ancestryTruncated},
		{name: "missing parent object", head: orphan, ancestor: a, limit: 10, want: ancestryTruncated},
		{name: "visit limit reached", head: d, ancestor: a, limit: 2, want: ancestryTruncated},
		{name: "visit limit allows the ancestor", head: d, ancestor: a, limit: 3, want: ancestryFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := findAncestor(s, tt.shallow, tt.head, tt.ancestor, tt.limit)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_cloneDepthApplies(t *testing.T) {
	g := NewWithT(t)
	g.Expect(cloneDepthApplies(nil)).To(BeTrue())
	g.Expect(cloneDepthApplies(&sourcev1.GitRepositoryRef{Branch: "main"})).To(BeTrue())
	g.Expect(cloneDepthApplies(&sourcev1.GitRepositoryRef{Name: "refs/tags/v1.0.0^{}"})).To(BeTrue())
	g.Expect(cloneDepthApplies(&sourcev1.GitRepositoryRef{Name: "refs/pull/420/head"})).To(BeFalse())
	g.Expect(cloneDepthApplies(&sourcev1.GitRepositoryRef{Branch: "main", Commit: "abc"})).To(BeFalse())
}
