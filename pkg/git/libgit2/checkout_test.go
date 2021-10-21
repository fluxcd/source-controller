/*
Copyright 2020 The Flux authors

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

package libgit2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	git2go "github.com/libgit2/git2go/v31"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
)

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	g := NewWithT(t)
	now := time.Now()

	tags := []struct{
		tag        string
		simple     bool
		commitTime time.Time
		tagTime    time.Time
	}{
		{
			tag: "v0.0.1",
			simple: true,
			commitTime: now,
		},
		{
			tag: "v0.1.0+build-1",
			simple: false,
			commitTime: now.Add(1 * time.Minute),
			tagTime: now.Add(1 * time.Hour), // This should be ignored during TS comparisons
		},
		{
			tag: "v0.1.0+build-2",
			simple: true,
			commitTime: now.Add(2 * time.Minute),
		},
		{
			tag: "0.2.0",
			simple: false,
			commitTime: now,
			tagTime: now,
		},
	}
	tests := []struct{
		name        string
		constraint  string
		expectError error
		expectTag   string
	}{
		{
			name: "Orders by SemVer",
			constraint: ">0.1.0",
			expectTag: "0.2.0",
		},
		{
			name: "Orders by SemVer and timestamp",
			constraint: "<0.2.0",
			expectTag: "v0.1.0+build-2",
		},
		{
			name: "Errors without match",
			constraint: ">=1.0.0",
			expectError: errors.New("no match found for semver: >=1.0.0"),
		},
	}

	repo, err := initBareRepo()
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()
	defer os.RemoveAll(repo.Path())

	for _, tt := range tags {
		cId, err := commit(repo, "tag.txt", tt.tag, tt.commitTime)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tag(repo, cId, tt.simple, tt.tag, tt.tagTime)
		if err != nil {
			t.Fatal(err)
		}
	}

	c, err := repo.Tags.List()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(c).To(HaveLen(len(tags)))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			semVer := CheckoutSemVer{
				semVer: tt.constraint,
			}
			tmpDir, _ := os.MkdirTemp("", "test")
			defer os.RemoveAll(tmpDir)

			_, ref, err := semVer.Checkout(context.TODO(), tmpDir, repo.Path(), &git.Auth{})
			if tt.expectError != nil {
				g.Expect(err).To(Equal(tt.expectError))
				g.Expect(ref).To(BeEmpty())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(ref).To(HavePrefix(tt.expectTag + "/"))
			content, err := os.ReadFile(filepath.Join(tmpDir, "tag.txt"))
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(content).To(BeEquivalentTo(tt.expectTag))
		})
	}
}

func initBareRepo() (*git2go.Repository, error) {
	tmpDir, err := os.MkdirTemp("", "git2go-")
	if err != nil {
		return nil, err
	}
	repo, err := git2go.InitRepository(tmpDir, false)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	return repo, nil
}

func headCommit(repo *git2go.Repository) (*git2go.Commit, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	defer head.Free()

	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, err
	}

	return commit, nil
}

func commit(repo *git2go.Repository, path, content string, time time.Time) (*git2go.Oid, error) {
	var parentC []*git2go.Commit
	head, err := headCommit(repo)
	if err == nil {
		defer head.Free()
		parentC = append(parentC, head)
	}

	index, err := repo.Index()
	if err != nil {
		return nil, err
	}
	defer index.Free()

	blobOID, err := repo.CreateBlobFromBuffer([]byte(content))
	if err != nil {
		return nil, err
	}

	entry := &git2go.IndexEntry{
		Mode: git2go.FilemodeBlob,
		Id:   blobOID,
		Path: path,
	}

	if err := index.Add(entry); err != nil {
		return nil, err
	}
	if err := index.Write(); err != nil {
		return nil, err
	}

	newTreeOID, err := index.WriteTree()
	if err != nil {
		return nil, err
	}

	tree, err := repo.LookupTree(newTreeOID)
	if err != nil {
		return nil, err
	}
	defer tree.Free()

	commit, err := repo.CreateCommit("HEAD", signature(time), signature(time), "Committing "+path, tree, parentC...)
	if err != nil {
		return nil, err
	}

	return commit, nil
}

func tag(repo *git2go.Repository, cId *git2go.Oid, simple bool, tag string, time time.Time) (*git2go.Oid, error) {
	commit, err := repo.LookupCommit(cId)
	if err != nil {
		return nil, err
	}
	if simple {
		return repo.Tags.CreateLightweight(tag, commit, false)
	}
	return repo.Tags.Create(tag, commit, signature(time), fmt.Sprintf("Annotated tag for %s", tag))
}

func signature(time time.Time) *git2go.Signature {
	return &git2go.Signature{
		Name:  "Jane Doe",
		Email: "author@example.com",
		When:  time,
	}
}
