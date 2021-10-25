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
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
)

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
					Transport: git.HTTP,
					Username:  user,
					Password:  pswd,
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
					Transport: git.HTTPS,
					Username:  user,
					Password:  pswd,
					CAFile:    ca,
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
				knownhosts, err := ssh.ScanHostKey(u.Host, 5*time.Second)
				g.Expect(err).ToNot(HaveOccurred())

				keygen := ssh.NewRSAGenerator(2048)
				pair, err := keygen.Generate()
				g.Expect(err).ToNot(HaveOccurred())

				return &git.AuthOptions{
					Host:       u.Host, // Without this libgit2 returns error "user cancelled hostkey check".
					Transport:  git.SSH,
					Username:   "git", // Without this libgit2 returns error "username does not match previous request".
					Identity:   pair.PrivateKey,
					KnownHosts: knownhosts,
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
			// TODO: Fix pkg/gittestserver InitRepo() bug to enable creating
			// custom branch.
			// branch := "main"
			branch := "master"
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

			tmpDir, err := os.MkdirTemp("", "test-checkout")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			tt.wantFunc(g, checkoutStrategy, tmpDir, repoURL, authOpts)
		}
	}

	// Run the test cases against the git implementations.
	for _, gitImpl := range gitImpls {
		for _, tt := range cases {
			t.Run(string(gitImpl)+"_"+tt.name, testFunc(tt, gitImpl))
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
