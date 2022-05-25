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

	"github.com/fluxcd/source-controller/pkg/git"
	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
)

func TestCheckoutBranch_Checkout(t *testing.T) {
	repo, err := initBareRepo(t)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()

	cfg, err := git2go.OpenDefault()
	if err != nil {
		t.Fatal(err)
	}

	// ignores the error here because it can be defaulted
	// https://github.blog/2020-07-27-highlights-from-git-2-28/#introducing-init-defaultbranch
	defaultBranch := "master"
	iter, err := cfg.NewIterator()
	if err != nil {
		t.Fatal(err)
	}
	for {
		val, e := iter.Next()
		if e != nil {
			break
		}
		if val.Name == "init.defaultbranch" {
			defaultBranch = val.Value
			break
		}
	}

	firstCommit, err := commitFile(repo, "branch", "init", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Branch off on first commit
	if err = createBranch(repo, "test", nil); err != nil {
		t.Fatal(err)
	}

	// Create second commit on default branch
	secondCommit, err := commitFile(repo, "branch", "second", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		branch         string
		filesCreated   map[string]string
		lastRevision   string
		expectedCommit string
		expectedErr    string
	}{
		{
			name:           "Default branch",
			branch:         defaultBranch,
			filesCreated:   map[string]string{"branch": "second"},
			expectedCommit: secondCommit.String(),
		},
		{
			name:           "Other branch",
			branch:         "test",
			filesCreated:   map[string]string{"branch": "init"},
			expectedCommit: firstCommit.String(),
		},
		{
			name:        "Non existing branch",
			branch:      "invalid",
			expectedErr: "reference 'refs/remotes/origin/invalid' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			branch := CheckoutBranch{
				Branch:       tt.branch,
				LastRevision: tt.lastRevision,
			}
			tmpDir := t.TempDir()

			cc, err := branch.Checkout(context.TODO(), tmpDir, repo.Path(), nil)
			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
				g.Expect(cc).To(BeNil())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.branch + "/" + tt.expectedCommit))
		})
	}
}

func TestCheckoutTag_Checkout(t *testing.T) {
	type testTag struct {
		name      string
		annotated bool
	}

	tests := []struct {
		name        string
		tagsInRepo  []testTag
		checkoutTag string
		expectErr   string
	}{
		{
			name:        "Tag",
			tagsInRepo:  []testTag{{"tag-1", false}},
			checkoutTag: "tag-1",
		},
		{
			name:        "Annotated",
			tagsInRepo:  []testTag{{"annotated", true}},
			checkoutTag: "annotated",
		},
		{
			name:        "Non existing tag",
			checkoutTag: "invalid",
			expectErr:   "unable to find 'invalid': no reference found for shorthand 'invalid'",
		},
		{
			name:        "Skip clone - last revision unchanged",
			tagsInRepo:  []testTag{{"tag-1", false}},
			checkoutTag: "tag-1",
		},
		{
			name:        "Last revision changed",
			tagsInRepo:  []testTag{{"tag-1", false}, {"tag-2", false}},
			checkoutTag: "tag-2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			repo, err := initBareRepo(t)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Free()

			// Collect tags and their associated commit for later reference.
			tagCommits := map[string]*git2go.Commit{}

			// Populate the repo with commits and tags.
			if tt.tagsInRepo != nil {
				for _, tr := range tt.tagsInRepo {
					var commit *git2go.Commit
					c, err := commitFile(repo, "tag", tr.name, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if commit, err = repo.LookupCommit(c); err != nil {
						t.Fatal(err)
					}
					_, err = tag(repo, commit.Id(), tr.annotated, tr.name, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					tagCommits[tr.name] = commit
				}
			}

			checkoutTag := CheckoutTag{
				Tag: tt.checkoutTag,
			}
			tmpDir := t.TempDir()

			cc, err := checkoutTag.Checkout(context.TODO(), tmpDir, repo.Path(), nil)
			if tt.expectErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectErr))
				g.Expect(cc).To(BeNil())
				return
			}

			// Check successful checkout results.
			targetTagCommit := tagCommits[tt.checkoutTag]
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.checkoutTag + "/" + targetTagCommit.Id().String()))

			g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
			g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.checkoutTag))
		})
	}
}

func TestCheckoutCommit_Checkout(t *testing.T) {
	g := NewWithT(t)

	repo, err := initBareRepo(t)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()

	c, err := commitFile(repo, "commit", "init", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = commitFile(repo, "commit", "second", time.Now()); err != nil {
		t.Fatal(err)
	}

	commit := CheckoutCommit{
		Commit: c.String(),
	}
	tmpDir := t.TempDir()

	cc, err := commit.Checkout(context.TODO(), tmpDir, repo.Path(), nil)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cc).ToNot(BeNil())
	g.Expect(cc.String()).To(Equal("HEAD/" + c.String()))
	g.Expect(filepath.Join(tmpDir, "commit")).To(BeARegularFile())
	g.Expect(os.ReadFile(filepath.Join(tmpDir, "commit"))).To(BeEquivalentTo("init"))

	commit = CheckoutCommit{
		Commit: "4dc3185c5fc94eb75048376edeb44571cece25f4",
	}
	tmpDir2 := t.TempDir()

	cc, err = commit.Checkout(context.TODO(), tmpDir2, repo.Path(), nil)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(HavePrefix("git checkout error: git commit '4dc3185c5fc94eb75048376edeb44571cece25f4' not found:"))
	g.Expect(cc).To(BeNil())
}

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	g := NewWithT(t)
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

	repo, err := initBareRepo(t)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()

	refs := make(map[string]string, len(tags))
	for _, tt := range tags {
		ref, err := commitFile(repo, "tag", tt.tag, tt.commitTime)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := repo.LookupCommit(ref)
		if err != nil {
			t.Fatal(err)
		}
		defer commit.Free()
		refs[tt.tag] = commit.Id().String()
		_, err = tag(repo, ref, tt.annotated, tt.tag, tt.tagTime)
		if err != nil {
			t.Fatal(err)
		}
	}

	c, err := repo.Tags.List()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(c).To(HaveLen(len(tags)))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			semVer := CheckoutSemVer{
				SemVer: tt.constraint,
			}
			tmpDir := t.TempDir()

			cc, err := semVer.Checkout(context.TODO(), tmpDir, repo.Path(), nil)
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

func initBareRepo(t *testing.T) (*git2go.Repository, error) {
	tmpDir := t.TempDir()
	repo, err := git2go.InitRepository(tmpDir, false)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

func createBranch(repo *git2go.Repository, branch string, commit *git2go.Commit) error {
	if commit == nil {
		var err error
		commit, err = headCommit(repo)
		if err != nil {
			return err
		}
		defer commit.Free()
	}
	_, err := repo.CreateBranch(branch, commit, false)
	return err
}

func commitFile(repo *git2go.Repository, path, content string, time time.Time) (*git2go.Oid, error) {
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

	treeID, err := index.WriteTree()
	if err != nil {
		return nil, err
	}

	tree, err := repo.LookupTree(treeID)
	if err != nil {
		return nil, err
	}
	defer tree.Free()

	c, err := repo.CreateCommit("HEAD", mockSignature(time), mockSignature(time), "Committing "+path, tree, parentC...)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func tag(repo *git2go.Repository, cId *git2go.Oid, annotated bool, tag string, time time.Time) (*git2go.Oid, error) {
	commit, err := repo.LookupCommit(cId)
	if err != nil {
		return nil, err
	}
	if annotated {
		return repo.Tags.Create(tag, commit, mockSignature(time), fmt.Sprintf("Annotated tag for %s", tag))
	}
	return repo.Tags.CreateLightweight(tag, commit, false)
}

func mockSignature(time time.Time) *git2go.Signature {
	return &git2go.Signature{
		Name:  "Jane Doe",
		Email: "author@example.com",
		When:  time,
	}
}

func TestInitializeRepoWithRemote(t *testing.T) {
	g := NewWithT(t)
	tmp := t.TempDir()
	ctx := context.TODO()
	testRepoURL := "https://example.com/foo/bar"
	testRepoURL2 := "https://example.com/foo/baz"
	authOpts, err := git.AuthOptionsWithoutSecret(testRepoURL)
	g.Expect(err).ToNot(HaveOccurred())
	authOpts2, err := git.AuthOptionsWithoutSecret(testRepoURL2)
	g.Expect(err).ToNot(HaveOccurred())

	// Fresh initialization.
	repo, remote, err := initializeRepoWithRemote(ctx, tmp, testRepoURL, authOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(repo.IsBare()).To(BeFalse())
	g.Expect(remote.Name()).To(Equal(defaultRemoteName))
	g.Expect(remote.Url()).To(Equal(testRepoURL))
	remote.Free()
	repo.Free()

	// Reinitialize to ensure it reuses the existing origin.
	repo, remote, err = initializeRepoWithRemote(ctx, tmp, testRepoURL, authOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(repo.IsBare()).To(BeFalse())
	g.Expect(remote.Name()).To(Equal(defaultRemoteName))
	g.Expect(remote.Url()).To(Equal(testRepoURL))
	remote.Free()
	repo.Free()

	// Reinitialize with a different remote URL for existing origin.
	_, _, err = initializeRepoWithRemote(ctx, tmp, testRepoURL2, authOpts2)
	g.Expect(err).To(HaveOccurred())
}
