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

package gogit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	. "github.com/onsi/gomega"
)

func TestCheckoutBranch_Checkout(t *testing.T) {
	repo, path, err := initRepo()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(path)

	firstCommit, err := commitFile(repo, "branch", "init", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if err = createBranch(repo, "test"); err != nil {
		t.Fatal(err)
	}

	secondCommit, err := commitFile(repo, "branch", "second", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		branch         string
		expectedCommit string
		expectedErr    string
	}{
		{
			name:           "Default branch",
			branch:         "master",
			expectedCommit: firstCommit.String(),
		},
		{
			name:           "Other branch",
			branch:         "test",
			expectedCommit: secondCommit.String(),
		},
		{
			name:        "Non existing branch",
			branch:      "invalid",
			expectedErr: "couldn't find remote ref \"refs/heads/invalid\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			branch := CheckoutBranch{
				Branch: tt.branch,
			}
			tmpDir, _ := os.MkdirTemp("", "test")
			defer os.RemoveAll(tmpDir)

			cc, err := branch.Checkout(context.TODO(), tmpDir, path, nil)
			if tt.expectedErr != "" {
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
				g.Expect(cc).To(BeNil())
				return
			}
			g.Expect(err).To(BeNil())
			g.Expect(cc.String()).To(Equal(tt.branch + "/" + tt.expectedCommit))
		})
	}
}

func TestCheckoutTag_Checkout(t *testing.T) {
	tests := []struct {
		name        string
		tag         string
		annotated   bool
		checkoutTag string
		expectTag   string
		expectErr   string
	}{
		{
			name:        "Tag",
			tag:         "tag-1",
			checkoutTag: "tag-1",
			expectTag:   "tag-1",
		},
		{
			name:        "Annotated",
			tag:         "annotated",
			annotated:   true,
			checkoutTag: "annotated",
			expectTag:   "annotated",
		},
		{
			name:        "Non existing tag",
			tag:         "tag-1",
			checkoutTag: "invalid",
			expectErr:   "couldn't find remote ref \"refs/tags/invalid\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			repo, path, err := initRepo()
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(path)

			var h plumbing.Hash
			if tt.tag != "" {
				h, err = commitFile(repo, "tag", tt.tag, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				_, err = tag(repo, h, !tt.annotated, tt.tag, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}

			tag := CheckoutTag{
				Tag: tt.checkoutTag,
			}
			tmpDir, _ := os.MkdirTemp("", "test")
			defer os.RemoveAll(tmpDir)

			cc, err := tag.Checkout(context.TODO(), tmpDir, path, nil)
			if tt.expectErr != "" {
				g.Expect(err.Error()).To(ContainSubstring(tt.expectErr))
				g.Expect(cc).To(BeNil())
				return
			}

			g.Expect(err).To(BeNil())
			g.Expect(cc.String()).To(Equal(tt.expectTag + "/" + h.String()))
			g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
			g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.tag))
		})
	}
}

func TestCheckoutCommit_Checkout(t *testing.T) {
	repo, path, err := initRepo()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(path)

	firstCommit, err := commitFile(repo, "commit", "init", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = createBranch(repo, "other-branch"); err != nil {
		t.Fatal(err)
	}
	secondCommit, err := commitFile(repo, "commit", "second", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		commit       string
		branch       string
		expectCommit string
		expectFile   string
		expectError  string
	}{
		{
			name:         "Commit",
			commit:       firstCommit.String(),
			expectCommit: "HEAD/" + firstCommit.String(),
			expectFile:   "init",
		},
		{
			name:         "Commit in specific branch",
			commit:       secondCommit.String(),
			branch:       "other-branch",
			expectCommit: "other-branch/" + secondCommit.String(),
			expectFile:   "second",
		},
		{
			name:        "Non existing commit",
			commit:      "a-random-invalid-commit",
			expectError: "failed to resolve commit object for 'a-random-invalid-commit': object not found",
		},
		{
			name:        "Non existing commit in specific branch",
			commit:      secondCommit.String(),
			branch:      "master",
			expectError: "object not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			commit := CheckoutCommit{
				Commit: tt.commit,
				Branch: tt.branch,
			}

			tmpDir, err := os.MkdirTemp("", "git2go")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(tmpDir)

			cc, err := commit.Checkout(context.TODO(), tmpDir, path, nil)
			if tt.expectError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectError))
				g.Expect(cc).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc).ToNot(BeNil())
			g.Expect(cc.String()).To(Equal(tt.expectCommit))
			g.Expect(filepath.Join(tmpDir, "commit")).To(BeARegularFile())
			g.Expect(os.ReadFile(filepath.Join(tmpDir, "commit"))).To(BeEquivalentTo(tt.expectFile))
		})
	}
}

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	now := time.Now()

	tags := []struct {
		tag        string
		annotated  bool
		commitTime time.Time
		tagTime    time.Time
	}{
		{
			tag:        "v0.0.1",
			annotated:  false,
			commitTime: now,
		},
		{
			tag:        "v0.1.0+build-1",
			annotated:  true,
			commitTime: now.Add(10 * time.Minute),
			tagTime:    now.Add(2 * time.Hour), // This should be ignored during TS comparisons
		},
		{
			tag:        "v0.1.0+build-2",
			annotated:  false,
			commitTime: now.Add(30 * time.Minute),
		},
		{
			tag:        "v0.1.0+build-3",
			annotated:  true,
			commitTime: now.Add(1 * time.Hour),
			tagTime:    now.Add(1 * time.Hour), // This should be ignored during TS comparisons
		},
		{
			tag:        "0.2.0",
			annotated:  true,
			commitTime: now,
			tagTime:    now,
		},
	}
	tests := []struct {
		name       string
		constraint string
		expectErr  error
		expectTag  string
	}{
		{
			name:       "Orders by SemVer",
			constraint: ">0.1.0",
			expectTag:  "0.2.0",
		},
		{
			name:       "Orders by SemVer and timestamp",
			constraint: "<0.2.0",
			expectTag:  "v0.1.0+build-3",
		},
		{
			name:       "Errors without match",
			constraint: ">=1.0.0",
			expectErr:  errors.New("no match found for semver: >=1.0.0"),
		},
	}

	repo, path, err := initRepo()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(path)

	refs := make(map[string]string, len(tags))
	for _, tt := range tags {
		ref, err := commitFile(repo, "tag", tt.tag, tt.commitTime)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tag(repo, ref, tt.annotated, tt.tag, tt.tagTime)
		if err != nil {
			t.Fatal(err)
		}
		refs[tt.tag] = ref.String()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			semVer := CheckoutSemVer{
				SemVer: tt.constraint,
			}
			tmpDir, _ := os.MkdirTemp("", "test")
			defer os.RemoveAll(tmpDir)

			cc, err := semVer.Checkout(context.TODO(), tmpDir, path, nil)
			if tt.expectErr != nil {
				g.Expect(err).To(Equal(tt.expectErr))
				g.Expect(cc).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.expectTag + "/" + refs[tt.expectTag]))
			g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
			g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.expectTag))
		})
	}
}

func initRepo() (*extgogit.Repository, string, error) {
	tmpDir, err := os.MkdirTemp("", "gogit")
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	sto := filesystem.NewStorage(osfs.New(tmpDir), cache.NewObjectLRUDefault())
	repo, err := extgogit.Init(sto, memfs.New())
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	return repo, tmpDir, err
}

func createBranch(repo *extgogit.Repository, branch string) error {
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	h, err := repo.Head()
	if err != nil {
		return err
	}
	return wt.Checkout(&extgogit.CheckoutOptions{
		Hash:   h.Hash(),
		Branch: plumbing.ReferenceName("refs/heads/" + branch),
		Create: true,
	})
}

func commitFile(repo *extgogit.Repository, path, content string, time time.Time) (plumbing.Hash, error) {
	wt, err := repo.Worktree()
	if err != nil {
		return plumbing.Hash{}, err
	}
	f, err := wt.Filesystem.Create(path)
	if err != nil {
		return plumbing.Hash{}, err
	}
	if _, err = f.Write([]byte(content)); err != nil {
		f.Close()
		return plumbing.Hash{}, err
	}
	if err = f.Close(); err != nil {
		return plumbing.Hash{}, err
	}
	if _, err = wt.Add(path); err != nil {
		return plumbing.Hash{}, err
	}
	return wt.Commit("Adding: "+path, &extgogit.CommitOptions{
		Author:    mockSignature(time),
		Committer: mockSignature(time),
	})
}

func tag(repo *extgogit.Repository, commit plumbing.Hash, annotated bool, tag string, time time.Time) (*plumbing.Reference, error) {
	var opts *extgogit.CreateTagOptions
	if annotated {
		opts = &extgogit.CreateTagOptions{
			Tagger:  mockSignature(time),
			Message: "Annotated tag for: " + tag,
		}
	}
	return repo.CreateTag(tag, commit, opts)
}

func mockSignature(time time.Time) *object.Signature {
	return &object.Signature{
		Name:  "Jane Doe",
		Email: "jane@example.com",
		When:  time,
	}
}
