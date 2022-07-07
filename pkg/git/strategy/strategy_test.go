/*
Copyright 2021 The Flux authors

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

package strategy

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
)

func TestMain(m *testing.M) {
	err := managed.InitManagedTransport()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize libgit2 managed transport: %s", err))
	}
	code := m.Run()
	os.Exit(code)
}

func TestCheckoutStrategyForImplementation_Auth(t *testing.T) {
	gitImpls := []git.Implementation{gogit.Implementation, libgit2.Implementation}

	type testCase struct {
		name         string
		transport    git.TransportType
		repoURLFunc  func(g *WithT, srv *gittestserver.GitServer, repoPath string) string
		authOptsFunc func(g *WithT, u *url.URL, user string, pswd string, ca []byte) *git.AuthOptions
		wantFunc     func(g *WithT, cs git.CheckoutStrategy, dir string, repoURL string, authOpts *git.AuthOptions)
	}

	cases := []testCase{
		{
			name:      "HTTP clone",
			transport: git.HTTP,
			repoURLFunc: func(g *WithT, srv *gittestserver.GitServer, repoPath string) string {
				return srv.HTTPAddressWithCredentials() + "/" + repoPath
			},
			authOptsFunc: func(g *WithT, u *url.URL, user string, pswd string, ca []byte) *git.AuthOptions {
				return &git.AuthOptions{
					Transport:           git.HTTP,
					Username:            user,
					Password:            pswd,
					TransportOptionsURL: getTransportOptionsURL(git.HTTP),
				}
			},
			wantFunc: func(g *WithT, cs git.CheckoutStrategy, dir string, repoURL string, authOpts *git.AuthOptions) {
				_, err := cs.Checkout(context.TODO(), dir, repoURL, authOpts)
				g.Expect(err).ToNot(HaveOccurred())
			},
		},
		{
			name:      "HTTPS clone",
			transport: git.HTTPS,
			repoURLFunc: func(g *WithT, srv *gittestserver.GitServer, repoPath string) string {
				return srv.HTTPAddress() + "/" + repoPath
			},
			authOptsFunc: func(g *WithT, u *url.URL, user, pswd string, ca []byte) *git.AuthOptions {
				return &git.AuthOptions{
					Transport:           git.HTTPS,
					Username:            user,
					Password:            pswd,
					CAFile:              ca,
					TransportOptionsURL: getTransportOptionsURL(git.HTTPS),
				}
			},
			wantFunc: func(g *WithT, cs git.CheckoutStrategy, dir, repoURL string, authOpts *git.AuthOptions) {
				_, err := cs.Checkout(context.TODO(), dir, repoURL, authOpts)
				g.Expect(err).ToNot(HaveOccurred())
			},
		},
		{
			name:      "SSH clone",
			transport: git.SSH,
			repoURLFunc: func(g *WithT, srv *gittestserver.GitServer, repoPath string) string {
				return getSSHRepoURL(srv.SSHAddress(), repoPath)
			},
			authOptsFunc: func(g *WithT, u *url.URL, user, pswd string, ca []byte) *git.AuthOptions {
				knownhosts, err := ssh.ScanHostKey(u.Host, 5*time.Second, git.HostKeyAlgos, false)
				g.Expect(err).ToNot(HaveOccurred())

				keygen := ssh.NewRSAGenerator(2048)
				pair, err := keygen.Generate()
				g.Expect(err).ToNot(HaveOccurred())

				return &git.AuthOptions{
					Host:                u.Host, // Without this libgit2 returns error "user cancelled hostkey check".
					Transport:           git.SSH,
					Username:            "git", // Without this libgit2 returns error "username does not match previous request".
					Identity:            pair.PrivateKey,
					KnownHosts:          knownhosts,
					TransportOptionsURL: getTransportOptionsURL(git.SSH),
				}
			},
			wantFunc: func(g *WithT, cs git.CheckoutStrategy, dir, repoURL string, authOpts *git.AuthOptions) {
				_, err := cs.Checkout(context.TODO(), dir, repoURL, authOpts)
				g.Expect(err).ToNot(HaveOccurred())
			},
		},
	}

	testFunc := func(tt testCase, impl git.Implementation) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			var examplePublicKey, examplePrivateKey, exampleCA []byte

			gitServer, err := gittestserver.NewTempGitServer()
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(gitServer.Root())

			username := "test-user"
			password := "test-password"
			gitServer.Auth(username, password)
			gitServer.KeyDir(gitServer.Root())

			// Start the HTTP/HTTPS server.
			if tt.transport == git.HTTPS {
				var err error
				examplePublicKey, err = os.ReadFile("testdata/certs/server.pem")
				g.Expect(err).ToNot(HaveOccurred())
				examplePrivateKey, err = os.ReadFile("testdata/certs/server-key.pem")
				g.Expect(err).ToNot(HaveOccurred())
				exampleCA, err = os.ReadFile("testdata/certs/ca.pem")
				g.Expect(err).ToNot(HaveOccurred())
				err = gitServer.StartHTTPS(examplePublicKey, examplePrivateKey, exampleCA, "example.com")
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(gitServer.StartHTTP()).ToNot(HaveOccurred())
			}

			defer gitServer.StopHTTP()

			// Start the SSH server.
			if tt.transport == git.SSH {
				g.Expect(gitServer.ListenSSH()).ToNot(HaveOccurred())
				go func() {
					gitServer.StartSSH()
				}()
				defer func() {
					g.Expect(gitServer.StopSSH()).To(Succeed())
				}()
			}

			// Initialize a git repo.
			branch := "main"
			repoPath := "bar/test-reponame"
			err = gitServer.InitRepo("testdata/repo1", branch, repoPath)
			g.Expect(err).ToNot(HaveOccurred())

			repoURL := tt.repoURLFunc(g, gitServer, repoPath)
			u, err := url.Parse(repoURL)
			g.Expect(err).ToNot(HaveOccurred())
			authOpts := tt.authOptsFunc(g, u, username, password, exampleCA)

			// Get the checkout strategy.
			checkoutOpts := git.CheckoutOptions{
				Branch: branch,
			}
			checkoutStrategy, err := CheckoutStrategyForImplementation(context.TODO(), impl, checkoutOpts)
			g.Expect(err).ToNot(HaveOccurred())

			tmpDir := t.TempDir()

			tt.wantFunc(g, checkoutStrategy, tmpDir, repoURL, authOpts)
		}
	}

	// Run the test cases against the git implementations.
	for _, gitImpl := range gitImpls {
		for _, tt := range cases {
			t.Run(fmt.Sprintf("%s_%s", gitImpl, tt.name), testFunc(tt, gitImpl))
		}
	}
}

func getSSHRepoURL(sshAddress, repoPath string) string {
	// This is expected to use 127.0.0.1, but host key
	// checking usually wants a hostname, so use
	// "localhost".
	sshURL := strings.Replace(sshAddress, "127.0.0.1", "localhost", 1)
	return sshURL + "/" + repoPath
}

func TestCheckoutStrategyForImplementation_SemVerCheckout(t *testing.T) {
	g := NewWithT(t)

	gitImpls := []git.Implementation{gogit.Implementation, libgit2.Implementation}

	// Setup git server and repo.
	gitServer, err := gittestserver.NewTempGitServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(gitServer.Root())
	username := "test-user"
	password := "test-password"
	gitServer.Auth(username, password)
	gitServer.KeyDir(gitServer.Root())
	g.Expect(gitServer.StartHTTP()).ToNot(HaveOccurred())
	defer gitServer.StopHTTP()

	repoPath := "bar/test-reponame"
	err = gitServer.InitRepo("testdata/repo1", "main", repoPath)
	g.Expect(err).ToNot(HaveOccurred())

	repoURL := gitServer.HTTPAddressWithCredentials() + "/" + repoPath

	authOpts := &git.AuthOptions{
		Transport:           git.HTTP,
		Username:            username,
		Password:            password,
		TransportOptionsURL: getTransportOptionsURL(git.HTTP),
	}

	// Create test tags in the repo.
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

	// Clone the repo locally.
	cloneDir := t.TempDir()
	repo, err := extgogit.PlainClone(cloneDir, false, &extgogit.CloneOptions{
		URL: repoURL,
	})
	g.Expect(err).ToNot(HaveOccurred())

	// Create commits and tags.
	// Keep a record of all the tags and commit refs.
	refs := make(map[string]string, len(tags))
	for _, tt := range tags {
		ref, err := commitFile(repo, "tag", tt.tag, tt.commitTime)
		g.Expect(err).ToNot(HaveOccurred())
		_, err = tag(repo, ref, tt.annotated, tt.tag, tt.tagTime)
		g.Expect(err).ToNot(HaveOccurred())
		refs[tt.tag] = ref.String()
	}

	// Push everything.
	err = repo.Push(&extgogit.PushOptions{
		RefSpecs: []config.RefSpec{"refs/*:refs/*"},
	})
	g.Expect(err).ToNot(HaveOccurred())

	// Test cases.
	type testCase struct {
		name       string
		constraint string
		expectErr  error
		expectTag  string
	}
	tests := []testCase{
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
	testFunc := func(tt testCase, impl git.Implementation) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			// Get the checkout strategy.
			checkoutOpts := git.CheckoutOptions{
				SemVer: tt.constraint,
			}
			checkoutStrategy, err := CheckoutStrategyForImplementation(context.TODO(), impl, checkoutOpts)
			g.Expect(err).ToNot(HaveOccurred())

			// Checkout and verify.
			tmpDir := t.TempDir()

			cc, err := checkoutStrategy.Checkout(context.TODO(), tmpDir, repoURL, authOpts)
			if tt.expectErr != nil {
				g.Expect(err).To(Equal(tt.expectErr))
				g.Expect(cc).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cc.String()).To(Equal(tt.expectTag + "/" + refs[tt.expectTag]))
			g.Expect(filepath.Join(tmpDir, "tag")).To(BeARegularFile())
			g.Expect(os.ReadFile(filepath.Join(tmpDir, "tag"))).To(BeEquivalentTo(tt.expectTag))
		}
	}

	// Run the test cases against the git implementations.
	for _, gitImpl := range gitImpls {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s_%s", gitImpl, tt.name), testFunc(tt, gitImpl))
		}
	}
}

func TestCheckoutStrategyForImplementation_WithCtxTimeout(t *testing.T) {
	gitImpls := []git.Implementation{gogit.Implementation, libgit2.Implementation}

	type testCase struct {
		name    string
		timeout time.Duration
		wantErr bool
	}

	cases := []testCase{
		{
			name:    "fails with short timeout",
			timeout: 100 * time.Millisecond,
			wantErr: true,
		},
		{
			name:    "succeeds with sufficient timeout",
			timeout: 5 * time.Second,
			wantErr: false,
		},
	}

	// Keeping it low to keep the test run time low.
	serverDelay := 500 * time.Millisecond

	testFunc := func(tt testCase, impl git.Implementation) func(t *testing.T) {
		return func(*testing.T) {
			g := NewWithT(t)

			gitServer, err := gittestserver.NewTempGitServer()
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(gitServer.Root())
			username := "test-user"
			password := "test-password"
			gitServer.Auth(username, password)
			gitServer.KeyDir(gitServer.Root())

			middleware := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(serverDelay)
					next.ServeHTTP(w, r)
				})
			}
			gitServer.AddHTTPMiddlewares(middleware)

			g.Expect(gitServer.StartHTTP()).ToNot(HaveOccurred())
			defer gitServer.StopHTTP()

			branch := "main"
			repoPath := "bar/test-reponame"
			err = gitServer.InitRepo("testdata/repo1", branch, repoPath)
			g.Expect(err).ToNot(HaveOccurred())

			repoURL := gitServer.HTTPAddressWithCredentials() + "/" + repoPath

			authOpts := &git.AuthOptions{
				Transport:           git.HTTP,
				Username:            username,
				Password:            password,
				TransportOptionsURL: getTransportOptionsURL(git.HTTP),
			}

			checkoutOpts := git.CheckoutOptions{
				Branch: branch,
			}
			checkoutStrategy, err := CheckoutStrategyForImplementation(context.TODO(), impl, checkoutOpts)
			g.Expect(err).ToNot(HaveOccurred())

			tmpDir := t.TempDir()

			checkoutCtx, cancel := context.WithTimeout(context.TODO(), tt.timeout)
			defer cancel()

			_, gotErr := checkoutStrategy.Checkout(checkoutCtx, tmpDir, repoURL, authOpts)
			if tt.wantErr {
				g.Expect(gotErr).To(HaveOccurred())
			} else {
				g.Expect(gotErr).ToNot(HaveOccurred())
			}
		}
	}

	// Run the test cases against the git implementations.
	for _, gitImpl := range gitImpls {
		for _, tt := range cases {
			t.Run(fmt.Sprintf("%s_%s", gitImpl, tt.name), testFunc(tt, gitImpl))
		}
	}
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
	if _, err := f.Write([]byte(content)); err != nil {
		if ferr := f.Close(); ferr != nil {
			return plumbing.Hash{}, ferr
		}
		return plumbing.Hash{}, err
	}
	if err := f.Close(); err != nil {
		return plumbing.Hash{}, err
	}
	if _, err := wt.Add(path); err != nil {
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

func getTransportOptionsURL(transport git.TransportType) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(transport) + "://" + string(b)
}
