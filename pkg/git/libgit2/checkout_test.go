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

	"github.com/fluxcd/pkg/gittestserver"
	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"

	mt "github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
)

func TestCheckoutBranch_unmanaged(t *testing.T) {
	checkoutBranch(t, false)
}

// checkoutBranch is a test helper function which runs the tests for checking out
// via CheckoutBranch.
func checkoutBranch(t *testing.T, managed bool) {
	// we use a HTTP Git server instead of a bare repo (for all tests in this
	// package), because our managed transports don't support the file protocol,
	// so we wouldn't actually be using our custom transports, if we used a bare
	// repo.
	server, err := gittestserver.NewTempGitServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(server.Root())

	err = server.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.StopHTTP()

	repoPath := "test.git"
	err = server.InitRepo("../testdata/git/repo", git.DefaultBranch, repoPath)
	if err != nil {
		t.Fatal(err)
	}

	repo, err := git2go.OpenRepository(filepath.Join(server.Root(), repoPath))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()

	defaultBranch := "master"

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
	repoURL := server.HTTPAddress() + "/" + repoPath

	tests := []struct {
		name                   string
		branch                 string
		filesCreated           map[string]string
		lastRevision           string
		expectedCommit         string
		expectedConcreteCommit bool
		expectedErr            string
	}{
		{
			name:                   "Default branch",
			branch:                 defaultBranch,
			filesCreated:           map[string]string{"branch": "second"},
			expectedCommit:         secondCommit.String(),
			expectedConcreteCommit: true,
		},
		{
			name:                   "Other branch",
			branch:                 "test",
			filesCreated:           map[string]string{"branch": "init"},
			expectedCommit:         firstCommit.String(),
			expectedConcreteCommit: true,
		},
		{
			name:                   "Non existing branch",
			branch:                 "invalid",
			expectedErr:            "reference 'refs/remotes/origin/invalid' not found",
			expectedConcreteCommit: true,
		},
		{
			name:                   "skip clone - lastRevision hasn't changed",
			branch:                 defaultBranch,
			filesCreated:           map[string]string{"branch": "second"},
			lastRevision:           fmt.Sprintf("%s/%s", defaultBranch, secondCommit.String()),
			expectedCommit:         secondCommit.String(),
			expectedConcreteCommit: false,
		},
		{
			name:                   "lastRevision is different",
			branch:                 defaultBranch,
			filesCreated:           map[string]string{"branch": "second"},
			lastRevision:           fmt.Sprintf("%s/%s", defaultBranch, firstCommit.String()),
			expectedCommit:         secondCommit.String(),
			expectedConcreteCommit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(mt.Enabled()).To(Equal(managed))

			branch := CheckoutBranch{
				Branch:       tt.branch,
				LastRevision: tt.lastRevision,
			}

			tmpDir := t.TempDir()
			authOpts := git.AuthOptions{
				TransportOptionsURL: getTransportOptionsURL(git.HTTP),
			}

			cc, err := branch.Checkout(context.TODO(), tmpDir, repoURL, &authOpts)
			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
				g.Expect(cc).To(BeNil())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.branch + "/" + tt.expectedCommit))
			if managed {
				g.Expect(git.IsConcreteCommit(*cc)).To(Equal(tt.expectedConcreteCommit))
			}

			if tt.expectedConcreteCommit {
				for k, v := range tt.filesCreated {
					g.Expect(filepath.Join(tmpDir, k)).To(BeARegularFile())
					g.Expect(os.ReadFile(filepath.Join(tmpDir, k))).To(BeEquivalentTo(v))
				}
			}
		})
	}
}

func TestCheckoutTag_unmanaged(t *testing.T) {
	checkoutTag(t, false)
}

// checkoutTag is a test helper function which runs the tests for checking out
// via CheckoutTag.
func checkoutTag(t *testing.T, managed bool) {
	type testTag struct {
		name      string
		annotated bool
	}

	tests := []struct {
		name                 string
		tagsInRepo           []testTag
		checkoutTag          string
		lastRevTag           string
		expectErr            string
		expectConcreteCommit bool
	}{
		{
			name:                 "Tag",
			tagsInRepo:           []testTag{{"tag-1", false}},
			checkoutTag:          "tag-1",
			expectConcreteCommit: true,
		},
		{
			name:                 "Annotated",
			tagsInRepo:           []testTag{{"annotated", true}},
			checkoutTag:          "annotated",
			expectConcreteCommit: true,
		},
		{
			name:        "Non existing tag",
			checkoutTag: "invalid",
			expectErr:   "unable to find 'invalid': no reference found for shorthand 'invalid'",
		},
		{
			name:                 "Skip clone - last revision unchanged",
			tagsInRepo:           []testTag{{"tag-1", false}},
			checkoutTag:          "tag-1",
			lastRevTag:           "tag-1",
			expectConcreteCommit: false,
		},
		{
			name:                 "Last revision changed",
			tagsInRepo:           []testTag{{"tag-1", false}, {"tag-2", false}},
			checkoutTag:          "tag-2",
			lastRevTag:           "tag-1",
			expectConcreteCommit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(mt.Enabled()).To(Equal(managed))

			server, err := gittestserver.NewTempGitServer()
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(server.Root())

			err = server.StartHTTP()
			g.Expect(err).ToNot(HaveOccurred())
			defer server.StopHTTP()

			repoPath := "test.git"
			err = server.InitRepo("../testdata/git/repo", git.DefaultBranch, repoPath)
			g.Expect(err).ToNot(HaveOccurred())

			repo, err := git2go.OpenRepository(filepath.Join(server.Root(), repoPath))
			g.Expect(err).ToNot(HaveOccurred())
			defer repo.Free()

			// Collect tags and their associated commit for later reference.
			tagCommits := map[string]*git2go.Commit{}

			repoURL := server.HTTPAddress() + "/" + repoPath

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
			// If last revision is provided, configure it.
			if tt.lastRevTag != "" {
				lc := tagCommits[tt.lastRevTag]
				checkoutTag.LastRevision = fmt.Sprintf("%s/%s", tt.lastRevTag, lc.Id().String())
			}

			tmpDir := t.TempDir()

			authOpts := git.AuthOptions{
				TransportOptionsURL: getTransportOptionsURL(git.HTTP),
			}
			cc, err := checkoutTag.Checkout(context.TODO(), tmpDir, repoURL, &authOpts)
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
			if managed {
				g.Expect(git.IsConcreteCommit(*cc)).To(Equal(tt.expectConcreteCommit))

			}

			// Check file content only when there's an actual checkout.
			if tt.lastRevTag != tt.checkoutTag {
				g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
				g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.checkoutTag))
			}
		})
	}
}

func TestCheckoutCommit_unmanaged(t *testing.T) {
	checkoutCommit(t, false)
}

// checkoutCommit is a test helper function which runs the tests for checking out
// via CheckoutCommit.
func checkoutCommit(t *testing.T, managed bool) {
	g := NewWithT(t)
	g.Expect(mt.Enabled()).To(Equal(managed))

	server, err := gittestserver.NewTempGitServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(server.Root())

	err = server.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.StopHTTP()

	repoPath := "test.git"
	err = server.InitRepo("../testdata/git/repo", git.DefaultBranch, repoPath)
	if err != nil {
		t.Fatal(err)
	}

	repo, err := git2go.OpenRepository(filepath.Join(server.Root(), repoPath))
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
	tmpDir := t.TempDir()
	authOpts := git.AuthOptions{
		TransportOptionsURL: getTransportOptionsURL(git.HTTP),
	}
	repoURL := server.HTTPAddress() + "/" + repoPath

	commit := CheckoutCommit{
		Commit: c.String(),
	}

	cc, err := commit.Checkout(context.TODO(), tmpDir, repoURL, &authOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cc).ToNot(BeNil())
	g.Expect(cc.String()).To(Equal("HEAD/" + c.String()))
	g.Expect(filepath.Join(tmpDir, "commit")).To(BeARegularFile())
	g.Expect(os.ReadFile(filepath.Join(tmpDir, "commit"))).To(BeEquivalentTo("init"))

	commit = CheckoutCommit{
		Commit: "4dc3185c5fc94eb75048376edeb44571cece25f4",
	}
	tmpDir2 := t.TempDir()

	cc, err = commit.Checkout(context.TODO(), tmpDir2, repoURL, &authOpts)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(HavePrefix("git checkout error: git commit '4dc3185c5fc94eb75048376edeb44571cece25f4' not found:"))
	g.Expect(cc).To(BeNil())
}

func TestCheckoutTagSemVer_unmanaged(t *testing.T) {
	checkoutSemVer(t, false)
}

// checkoutSemVer is a test helper function which runs the tests for checking out
// via CheckoutSemVer.
func checkoutSemVer(t *testing.T, managed bool) {
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

	server, err := gittestserver.NewTempGitServer()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(server.Root())

	err = server.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.StopHTTP()

	repoPath := "test.git"
	err = server.InitRepo("../testdata/git/repo", git.DefaultBranch, repoPath)
	if err != nil {
		t.Fatal(err)
	}

	repo, err := git2go.OpenRepository(filepath.Join(server.Root(), repoPath))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Free()
	repoURL := server.HTTPAddress() + "/" + repoPath

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
			g.Expect(mt.Enabled()).To(Equal(managed))

			semVer := CheckoutSemVer{
				SemVer: tt.constraint,
			}

			tmpDir := t.TempDir()
			authOpts := git.AuthOptions{
				TransportOptionsURL: getTransportOptionsURL(git.HTTP),
			}

			cc, err := semVer.Checkout(context.TODO(), tmpDir, repoURL, &authOpts)
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
	repo, err := git2go.InitRepository(tmpDir, true)
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

	g.Expect(mt.Enabled()).To(BeFalse())
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

func TestCheckoutStrategyForOptions(t *testing.T) {
	tests := []struct {
		name          string
		opts          git.CheckoutOptions
		expectedStrat git.CheckoutStrategy
	}{
		{
			name: "commit works",
			opts: git.CheckoutOptions{
				Commit: "commit",
			},
			expectedStrat: &CheckoutCommit{
				Commit: "commit",
			},
		},
		{
			name: "semver works",
			opts: git.CheckoutOptions{
				SemVer: ">= 1.0.0",
			},
			expectedStrat: &CheckoutSemVer{
				SemVer: ">= 1.0.0",
			},
		},
		{
			name: "tag with latest revision works",
			opts: git.CheckoutOptions{
				Tag:          "v0.1.0",
				LastRevision: "ar34oi2njrngjrng",
			},
			expectedStrat: &CheckoutTag{
				Tag:          "v0.1.0",
				LastRevision: "ar34oi2njrngjrng",
			},
		},
		{
			name: "branch with latest revision works",
			opts: git.CheckoutOptions{
				Branch:       "main",
				LastRevision: "rrgij20mkmrg",
			},
			expectedStrat: &CheckoutBranch{
				Branch:       "main",
				LastRevision: "rrgij20mkmrg",
			},
		},
		{
			name: "empty branch falls back to default",
			opts: git.CheckoutOptions{},
			expectedStrat: &CheckoutBranch{
				Branch: git.DefaultBranch,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			strat := CheckoutStrategyForOptions(context.TODO(), tt.opts)
			g.Expect(strat).To(Equal(tt.expectedStrat))
		})
	}
}
