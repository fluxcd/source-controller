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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/gitkit"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	. "github.com/onsi/gomega"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
)

const testRepositoryPath = "../testdata/git/repo"

func TestCheckoutBranch_Checkout(t *testing.T) {
	repo, path, err := initRepo(t)
	if err != nil {
		t.Fatal(err)
	}

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
			branch:                 "master",
			filesCreated:           map[string]string{"branch": "init"},
			expectedCommit:         firstCommit.String(),
			expectedConcreteCommit: true,
		},
		{
			name:                   "skip clone if LastRevision hasn't changed",
			branch:                 "master",
			filesCreated:           map[string]string{"branch": "init"},
			lastRevision:           fmt.Sprintf("master/%s", firstCommit.String()),
			expectedCommit:         firstCommit.String(),
			expectedConcreteCommit: false,
		},
		{
			name:                   "Other branch - revision has changed",
			branch:                 "test",
			filesCreated:           map[string]string{"branch": "second"},
			lastRevision:           fmt.Sprintf("master/%s", firstCommit.String()),
			expectedCommit:         secondCommit.String(),
			expectedConcreteCommit: true,
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
				Branch:       tt.branch,
				LastRevision: tt.lastRevision,
			}
			tmpDir := t.TempDir()

			cc, err := branch.Checkout(context.TODO(), tmpDir, path, nil)
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
		expectConcreteCommit bool
		expectErr            string
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
			name: "Non existing tag",
			// Without this go-git returns error "remote repository is empty".
			tagsInRepo:  []testTag{{"tag-1", false}},
			checkoutTag: "invalid",
			expectErr:   "couldn't find remote ref \"refs/tags/invalid\"",
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

			repo, path, err := initRepo(t)
			if err != nil {
				t.Fatal(err)
			}

			// Collect tags and their associated commit hash for later
			// reference.
			tagCommits := map[string]string{}

			// Populate the repo with commits and tags.
			if tt.tagsInRepo != nil {
				for _, tr := range tt.tagsInRepo {
					h, err := commitFile(repo, "tag", tr.name, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					_, err = tag(repo, h, tr.annotated, tr.name, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					tagCommits[tr.name] = h.String()
				}
			}

			checkoutTag := CheckoutTag{
				Tag: tt.checkoutTag,
			}
			// If last revision is provided, configure it.
			if tt.lastRevTag != "" {
				lc := tagCommits[tt.lastRevTag]
				checkoutTag.LastRevision = fmt.Sprintf("%s/%s", tt.lastRevTag, lc)
			}

			tmpDir := t.TempDir()

			cc, err := checkoutTag.Checkout(context.TODO(), tmpDir, path, nil)
			if tt.expectErr != "" {
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectErr))
				g.Expect(cc).To(BeNil())
				return
			}

			// Check successful checkout results.
			g.Expect(git.IsConcreteCommit(*cc)).To(Equal(tt.expectConcreteCommit))
			targetTagHash := tagCommits[tt.checkoutTag]
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.checkoutTag + "/" + targetTagHash))

			// Check file content only when there's an actual checkout.
			if tt.lastRevTag != tt.checkoutTag {
				g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
				g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.checkoutTag))
			}
		})
	}
}

func TestCheckoutCommit_Checkout(t *testing.T) {
	repo, path, err := initRepo(t)
	if err != nil {
		t.Fatal(err)
	}

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

			tmpDir := t.TempDir()

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

	repo, path, err := initRepo(t)
	if err != nil {
		t.Fatal(err)
	}

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
			tmpDir := t.TempDir()

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

// Test_KeyTypes assures support for the different types of keys
// for SSH Authentication supported by Flux.
func Test_KeyTypes(t *testing.T) {
	tests := []struct {
		name       string
		keyType    ssh.KeyPairType
		authorized bool
		wantErr    string
	}{
		{name: "RSA 4096", keyType: ssh.RSA_4096, authorized: true},
		{name: "ECDSA P256", keyType: ssh.ECDSA_P256, authorized: true},
		{name: "ECDSA P384", keyType: ssh.ECDSA_P384, authorized: true},
		{name: "ECDSA P521", keyType: ssh.ECDSA_P521, authorized: true},
		{name: "ED25519", keyType: ssh.ED25519, authorized: true},
		{name: "unauthorized key", keyType: ssh.RSA_4096, wantErr: "unable to authenticate, attempted methods [none publickey], no supported methods remain"},
	}

	serverRootDir := t.TempDir()
	server := gittestserver.NewGitServer(serverRootDir)

	// Auth needs to be called, for authentication to be enabled.
	server.Auth("", "")

	var authorizedPublicKey string
	server.PublicKeyLookupFunc(func(content string) (*gitkit.PublicKey, error) {
		authedKey := strings.TrimSuffix(string(authorizedPublicKey), "\n")
		if authedKey == content {
			return &gitkit.PublicKey{Content: content}, nil
		}
		return nil, fmt.Errorf("pubkey provided '%s' does not match %s", content, authedKey)
	})

	g := NewWithT(t)
	timeout := 5 * time.Second

	server.KeyDir(filepath.Join(server.Root(), "keys"))
	g.Expect(server.ListenSSH()).To(Succeed())

	go func() {
		server.StartSSH()
	}()
	defer server.StopSSH()

	repoPath := "test.git"
	err := server.InitRepo(testRepositoryPath, git.DefaultBranch, repoPath)
	g.Expect(err).NotTo(HaveOccurred())

	sshURL := server.SSHAddress()
	repoURL := sshURL + "/" + repoPath

	// Fetch host key.
	u, err := url.Parse(sshURL)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(u.Host).ToNot(BeEmpty())

	knownHosts, err := ssh.ScanHostKey(u.Host, timeout, git.HostKeyAlgos, false)
	g.Expect(err).ToNot(HaveOccurred())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Generate ssh keys based on key type.
			kp, err := ssh.GenerateKeyPair(tt.keyType)
			g.Expect(err).ToNot(HaveOccurred())

			// Update authorized key to ensure only the new key is valid on the server.
			if tt.authorized {
				authorizedPublicKey = string(kp.PublicKey)
			}

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
			commit, err := branchCheckoutStrat.Checkout(ctx, tmpDir, repoURL, authOpts)

			if tt.wantErr == "" {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(commit).ToNot(BeNil())

				// Confirm checkout actually happened.
				d, err := os.ReadDir(tmpDir)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(d).To(HaveLen(2)) // .git and foo.txt
			} else {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).Should(ContainSubstring(tt.wantErr))
			}
		})
	}
}

// Test_KeyExchangeAlgos assures support for the different
// types of SSH key exchange algorithms supported by Flux.
func Test_KeyExchangeAlgos(t *testing.T) {
	tests := []struct {
		name      string
		ClientKex []string
		ServerKex []string
		wantErr   string
	}{
		{
			name:      "support for kex: diffie-hellman-group14-sha1",
			ClientKex: []string{"diffie-hellman-group14-sha1"},
			ServerKex: []string{"diffie-hellman-group14-sha1"},
		},
		{
			name:      "support for kex: diffie-hellman-group14-sha256",
			ClientKex: []string{"diffie-hellman-group14-sha256"},
			ServerKex: []string{"diffie-hellman-group14-sha256"},
		},
		{
			name:      "support for kex: curve25519-sha256",
			ClientKex: []string{"curve25519-sha256"},
			ServerKex: []string{"curve25519-sha256"},
		},
		{
			name:      "support for kex: ecdh-sha2-nistp256",
			ClientKex: []string{"ecdh-sha2-nistp256"},
			ServerKex: []string{"ecdh-sha2-nistp256"},
		},
		{
			name:      "support for kex: ecdh-sha2-nistp384",
			ClientKex: []string{"ecdh-sha2-nistp384"},
			ServerKex: []string{"ecdh-sha2-nistp384"},
		},
		{
			name:      "support for kex: ecdh-sha2-nistp521",
			ClientKex: []string{"ecdh-sha2-nistp521"},
			ServerKex: []string{"ecdh-sha2-nistp521"},
		},
		{
			name:      "support for kex: curve25519-sha256@libssh.org",
			ClientKex: []string{"curve25519-sha256@libssh.org"},
			ServerKex: []string{"curve25519-sha256@libssh.org"},
		},
		{
			name:      "non-matching kex",
			ClientKex: []string{"ecdh-sha2-nistp521"},
			ServerKex: []string{"curve25519-sha256@libssh.org"},
			wantErr:   "ssh: no common algorithm for key exchange; client offered: [ecdh-sha2-nistp521 ext-info-c], server offered: [curve25519-sha256@libssh.org]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			timeout := 5 * time.Second

			serverRootDir := t.TempDir()
			server := gittestserver.NewGitServer(serverRootDir).WithSSHConfig(&cryptossh.ServerConfig{
				Config: cryptossh.Config{
					KeyExchanges: tt.ServerKex,
				},
			})

			// Set what Client Key Exchange Algos to send
			git.KexAlgos = tt.ClientKex

			server.KeyDir(filepath.Join(server.Root(), "keys"))
			g.Expect(server.ListenSSH()).To(Succeed())

			go func() {
				server.StartSSH()
			}()
			defer server.StopSSH()

			repoPath := "test.git"
			err := server.InitRepo(testRepositoryPath, git.DefaultBranch, repoPath)
			g.Expect(err).NotTo(HaveOccurred())

			sshURL := server.SSHAddress()
			repoURL := sshURL + "/" + repoPath

			// Fetch host key.
			u, err := url.Parse(sshURL)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(u.Host).ToNot(BeEmpty())

			knownHosts, err := ssh.ScanHostKey(u.Host, timeout, git.HostKeyAlgos, false)
			g.Expect(err).ToNot(HaveOccurred())

			// No authentication is required for this test, but it is
			// used here to make the Checkout logic happy.
			kp, err := ssh.GenerateKeyPair(ssh.ED25519)
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
			_, err = branchCheckoutStrat.Checkout(ctx, tmpDir, repoURL, authOpts)
			if tt.wantErr != "" {
				g.Expect(err).Error().Should(HaveOccurred())
				g.Expect(err.Error()).Should(ContainSubstring(tt.wantErr))
			} else {
				g.Expect(err).Error().ShouldNot(HaveOccurred())
			}
		})
	}
}

// TestHostKeyAlgos assures support for the different
// types of SSH Host Key algorithms supported by Flux.
func TestHostKeyAlgos(t *testing.T) {
	tests := []struct {
		name               string
		keyType            ssh.KeyPairType
		ClientHostKeyAlgos []string
		hashHostNames      bool
	}{
		{
			name:               "support for hostkey: ssh-rsa",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"ssh-rsa"},
		},
		{
			name:               "support for hostkey: rsa-sha2-256",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"rsa-sha2-256"},
		},
		{
			name:               "support for hostkey: rsa-sha2-512",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"rsa-sha2-512"},
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp256",
			keyType:            ssh.ECDSA_P256,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp256"},
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp384",
			keyType:            ssh.ECDSA_P384,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp384"},
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp521",
			keyType:            ssh.ECDSA_P521,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp521"},
		},
		{
			name:               "support for hostkey: ssh-ed25519",
			keyType:            ssh.ED25519,
			ClientHostKeyAlgos: []string{"ssh-ed25519"},
		},
		{
			name:               "support for hostkey: ssh-rsa with hashed host names",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"ssh-rsa"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: rsa-sha2-256 with hashed host names",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"rsa-sha2-256"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: rsa-sha2-512 with hashed host names",
			keyType:            ssh.RSA_4096,
			ClientHostKeyAlgos: []string{"rsa-sha2-512"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp256 with hashed host names",
			keyType:            ssh.ECDSA_P256,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp256"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp384 with hashed host names",
			keyType:            ssh.ECDSA_P384,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp384"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: ecdsa-sha2-nistp521 with hashed host names",
			keyType:            ssh.ECDSA_P521,
			ClientHostKeyAlgos: []string{"ecdsa-sha2-nistp521"},
			hashHostNames:      true,
		},
		{
			name:               "support for hostkey: ssh-ed25519 with hashed host names",
			keyType:            ssh.ED25519,
			ClientHostKeyAlgos: []string{"ssh-ed25519"},
			hashHostNames:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			timeout := 5 * time.Second

			sshConfig := &cryptossh.ServerConfig{}

			// Generate new keypair for the server to use for HostKeys.
			hkp, err := ssh.GenerateKeyPair(tt.keyType)
			g.Expect(err).NotTo(HaveOccurred())
			p, err := cryptossh.ParseRawPrivateKey(hkp.PrivateKey)
			g.Expect(err).NotTo(HaveOccurred())

			// Add key to server.
			signer, err := cryptossh.NewSignerFromKey(p)
			g.Expect(err).NotTo(HaveOccurred())
			sshConfig.AddHostKey(signer)

			serverRootDir := t.TempDir()
			server := gittestserver.NewGitServer(serverRootDir).WithSSHConfig(sshConfig)

			// Set what HostKey Algos will be accepted from a client perspective.
			git.HostKeyAlgos = tt.ClientHostKeyAlgos

			keyDir := filepath.Join(server.Root(), "keys")
			server.KeyDir(keyDir)
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

			knownHosts, err := ssh.ScanHostKey(u.Host, timeout, git.HostKeyAlgos, tt.hashHostNames)
			g.Expect(err).ToNot(HaveOccurred())

			// No authentication is required for this test, but it is
			// used here to make the Checkout logic happy.
			kp, err := ssh.GenerateKeyPair(ssh.ED25519)
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
			_, err = branchCheckoutStrat.Checkout(ctx, tmpDir, repoURL, authOpts)
			g.Expect(err).Error().ShouldNot(HaveOccurred())
		})
	}
}

func initRepo(t *testing.T) (*extgogit.Repository, string, error) {
	tmpDir := t.TempDir()
	sto := filesystem.NewStorage(osfs.New(tmpDir), cache.NewObjectLRUDefault())
	repo, err := extgogit.Init(sto, memfs.New())
	if err != nil {
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
