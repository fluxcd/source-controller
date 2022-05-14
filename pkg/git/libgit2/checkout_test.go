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
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"

	"github.com/fluxcd/source-controller/pkg/git"
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
			g.Expect(git.IsConcreteCommit(*cc)).To(Equal(tt.expectedConcreteCommit))

			if tt.expectedConcreteCommit {
				for k, v := range tt.filesCreated {
					g.Expect(filepath.Join(tmpDir, k)).To(BeARegularFile())
					g.Expect(os.ReadFile(filepath.Join(tmpDir, k))).To(BeEquivalentTo(v))
				}
			}
		})
	}
}

func TestCheckoutTag_Checkout(t *testing.T) {
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
			// If last revision is provided, configure it.
			if tt.lastRevTag != "" {
				lc := tagCommits[tt.lastRevTag]
				checkoutTag.LastRevision = fmt.Sprintf("%s/%s", tt.lastRevTag, lc.Id().String())
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
			g.Expect(git.IsConcreteCommit(*cc)).To(Equal(tt.expectConcreteCommit))
			targetTagCommit := tagCommits[tt.checkoutTag]
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.checkoutTag + "/" + targetTagCommit.Id().String()))

			// Check file content only when there's an actual checkout.
			if tt.lastRevTag != tt.checkoutTag {
				g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
				g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.checkoutTag))
			}
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

// This test is specifically to detect regression in libgit2's ED25519 key
// support for client authentication.
// Refer: https://github.com/fluxcd/source-controller/issues/399
func TestCheckout_ED25519(t *testing.T) {
	g := NewWithT(t)
	timeout := 5 * time.Second

	// Create a git test server.
	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(server.Root())
	server.Auth("test-user", "test-pswd")
	server.AutoCreate()

	server.KeyDir(filepath.Join(server.Root(), "keys"))
	g.Expect(server.ListenSSH()).To(Succeed())

	go func() {
		server.StartSSH()
	}()
	defer server.StopSSH()

	repoPath := "test.git"

	err = server.InitRepo(testRepositoryPath, git.DefaultBranch, repoPath)
	g.Expect(err).NotTo(HaveOccurred())

	sshURL := server.SSHAddress()
	repoURL := sshURL + "/" + repoPath

	// Fetch host key.
	u, err := url.Parse(sshURL)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(u.Host).ToNot(BeEmpty())
	knownHosts, err := ssh.ScanHostKey(u.Host, timeout, git.HostKeyAlgos)
	g.Expect(err).ToNot(HaveOccurred())

	kp, err := ssh.NewEd25519Generator().Generate()
	g.Expect(err).ToNot(HaveOccurred())

	secret := corev1.Secret{
		Data: map[string][]byte{
			"identity":    kp.PrivateKey,
			"known_hosts": knownHosts,
		},
	}

	authOpts, err := git.AuthOptionsFromSecret(repoURL, &secret)
	g.Expect(err).ToNot(HaveOccurred())

	// Prepare for checkout.
	branchCheckoutStrat := &CheckoutBranch{Branch: git.DefaultBranch}
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	// Checkout the repo.
	// This should always fail because the generated key above isn't present in
	// the git server.
	_, err = branchCheckoutStrat.Checkout(ctx, tmpDir, repoURL, authOpts)
	g.Expect(err).ToNot(HaveOccurred())
}
