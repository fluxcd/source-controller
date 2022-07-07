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

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/fluxcd/pkg/gittestserver"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
	"github.com/fluxcd/source-controller/pkg/git/strategy"
)

// These tests are run in a different _test.go file because go-git uses the ProxyFromEnvironment function of the net/http package
// which caches the Proxy settings, hence not including other tests in the same file ensures a clean proxy setup for the tests to run.
func TestCheckoutStrategyForImplementation_Proxied(t *testing.T) {
	managed.InitManagedTransport()

	type cleanupFunc func()

	type testCase struct {
		name          string
		gitImpl       git.Implementation
		url           string
		branch        string
		setupGitProxy func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc)
		shortTimeout  bool
		wantUsedProxy bool
		wantError     bool
	}

	g := NewWithT(t)

	// Get a free port for proxy to use.
	l, err := net.Listen("tcp", ":0")
	g.Expect(err).ToNot(HaveOccurred())
	proxyAddr := fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port)
	g.Expect(l.Close()).ToNot(HaveOccurred())

	cases := []testCase{
		{
			name:    "gogit_HTTP_PROXY",
			gitImpl: gogit.Implementation,
			url:     "http://example.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				// Create the git server.
				gitServer, err := gittestserver.NewTempGitServer()
				g.Expect(err).ToNot(HaveOccurred())

				username := "test-user"
				password := "test-password"
				gitServer.Auth(username, password)
				gitServer.KeyDir(gitServer.Root())

				g.Expect(gitServer.StartHTTP()).ToNot(HaveOccurred())

				// Initialize a git repo.
				err = gitServer.InitRepo("../testdata/repo1", "main", "bar/test-reponame")
				g.Expect(err).ToNot(HaveOccurred())

				u, err := url.Parse(gitServer.HTTPAddress())
				g.Expect(err).ToNot(HaveOccurred())

				// The request is being forwarded to the local test git server in this handler.
				var proxyHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					userAgent := req.Header.Get("User-Agent")
					if strings.Contains(req.Host, "example.com") && strings.Contains(userAgent, "git") {
						atomic.AddInt32(proxiedRequests, 1)
						req.Host = u.Host
						req.URL.Host = req.Host
						return req, nil
					}
					// Reject if it isnt our request.
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "")
				}
				proxy.OnRequest().Do(proxyHandler)

				return &git.AuthOptions{
						Transport: git.HTTP,
						Username:  username,
						Password:  password,
					}, func() {
						os.RemoveAll(gitServer.Root())
						gitServer.StopHTTP()
					}
			},
			shortTimeout:  false,
			wantUsedProxy: true,
			wantError:     false,
		},
		{
			name:    "gogit_HTTPS_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://github.com/git-fixtures/basic",
			branch:  "master",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// We don't check for user agent as this handler is only going to process CONNECT requests, and because Go's net/http
					// is the one making such a request on behalf of go-git, adding a check for the go net/http user agent (Go-http-client)
					// would only allow false positives from any request originating from Go's net/http.
					if strings.Contains(host, "github.com") {
						atomic.AddInt32(proxiedRequests, 1)
						return goproxy.OkConnect, host
					}
					// Reject if it isnt our request.
					return goproxy.RejectConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				// go-git does not allow to use an HTTPS proxy and a custom root CA at the same time.
				// See https://github.com/fluxcd/source-controller/pull/524#issuecomment-1006673163.
				return nil, func() {}
			},
			shortTimeout:  false,
			wantUsedProxy: true,
			wantError:     false,
		},
		{
			name:    "gogit_NO_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://192.0.2.1/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// We shouldn't hit the proxy so we just want to check for any interaction, then reject.
					atomic.AddInt32(proxiedRequests, 1)
					return goproxy.RejectConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				return nil, func() {}
			},
			shortTimeout:  true,
			wantUsedProxy: false,
			wantError:     true,
		},
		{
			name:    "libgit2_HTTPS_PROXY",
			gitImpl: libgit2.Implementation,
			url:     "https://example.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				// Create the git server.
				gitServer, err := gittestserver.NewTempGitServer()
				g.Expect(err).ToNot(HaveOccurred())

				username := "test-user"
				password := "test-password"
				gitServer.Auth(username, password)
				gitServer.KeyDir(gitServer.Root())

				// Start the HTTPS server.
				examplePublicKey, err := os.ReadFile("../testdata/certs/server.pem")
				g.Expect(err).ToNot(HaveOccurred())
				examplePrivateKey, err := os.ReadFile("../testdata/certs/server-key.pem")
				g.Expect(err).ToNot(HaveOccurred())
				exampleCA, err := os.ReadFile("../testdata/certs/ca.pem")
				g.Expect(err).ToNot(HaveOccurred())
				err = gitServer.StartHTTPS(examplePublicKey, examplePrivateKey, exampleCA, "example.com")
				g.Expect(err).ToNot(HaveOccurred())

				// Initialize a git repo.
				repoPath := "bar/test-reponame"
				err = gitServer.InitRepo("../testdata/repo1", "main", repoPath)
				g.Expect(err).ToNot(HaveOccurred())

				u, err := url.Parse(gitServer.HTTPAddress())
				g.Expect(err).ToNot(HaveOccurred())

				// The request is being forwarded to the local test git server in this handler.
				// The certificate used here is valid for both example.com and localhost.
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					defer managed.RemoveTransportOptions("https://example.com/bar/test-reponame")
					// Check if the host matches with the git server address and the user-agent is the expected git client.
					userAgent := ctx.Req.Header.Get("User-Agent")
					if strings.Contains(host, "example.com") && strings.Contains(userAgent, "libgit2") {
						atomic.AddInt32(proxiedRequests, 1)
						return goproxy.OkConnect, u.Host
					}
					// Reject if it isn't our request.
					return goproxy.RejectConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				return &git.AuthOptions{
						Transport:           git.HTTPS,
						Username:            username,
						Password:            password,
						CAFile:              exampleCA,
						TransportOptionsURL: "https://proxy-test",
					}, func() {
						os.RemoveAll(gitServer.Root())
						gitServer.StopHTTP()
					}
			},
			shortTimeout:  false,
			wantUsedProxy: true,
			wantError:     false,
		},
		{
			name:    "libgit2_HTTP_PROXY",
			gitImpl: libgit2.Implementation,
			url:     "http://example.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				// Create the git server.
				gitServer, err := gittestserver.NewTempGitServer()
				g.Expect(err).ToNot(HaveOccurred())

				err = gitServer.StartHTTP()
				g.Expect(err).ToNot(HaveOccurred())

				// Initialize a git repo.
				repoPath := "bar/test-reponame"
				err = gitServer.InitRepo("../testdata/repo1", "main", repoPath)
				g.Expect(err).ToNot(HaveOccurred())

				u, err := url.Parse(gitServer.HTTPAddress())
				g.Expect(err).ToNot(HaveOccurred())

				// The request is being forwarded to the local test git server in this handler.
				// The certificate used here is valid for both example.com and localhost.
				var proxyHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					userAgent := req.Header.Get("User-Agent")
					if strings.Contains(req.Host, "example.com") && strings.Contains(userAgent, "git") {
						atomic.AddInt32(proxiedRequests, 1)
						req.Host = u.Host
						req.URL.Host = req.Host
						return req, nil
					}
					// Reject if it isnt our request.
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "")
				}
				proxy.OnRequest().Do(proxyHandler)

				return &git.AuthOptions{
						Transport:           git.HTTP,
						TransportOptionsURL: "http://proxy-test",
					}, func() {
						os.RemoveAll(gitServer.Root())
						gitServer.StopHTTP()
					}
			},
			shortTimeout:  false,
			wantUsedProxy: true,
			wantError:     false,
		},
		{
			name:    "gogit_HTTPS_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://github.com/git-fixtures/basic",
			branch:  "master",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// We don't check for user agent as this handler is only going to process CONNECT requests, and because Go's net/http
					// is the one making such a request on behalf of go-git, adding a check for the go net/http user agent (Go-http-client)
					// would only allow false positives from any request originating from Go's net/http.
					if strings.Contains(host, "github.com") {
						atomic.AddInt32(proxiedRequests, 1)
						return goproxy.OkConnect, host
					}
					// Reject if it isnt our request.
					return goproxy.RejectConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				// go-git does not allow to use an HTTPS proxy and a custom root CA at the same time.
				// See https://github.com/fluxcd/source-controller/pull/524#issuecomment-1006673163.
				return nil, func() {}
			},
			shortTimeout:  false,
			wantUsedProxy: true,
			wantError:     false,
		},
		{
			name:    "gogit_NO_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://192.0.2.1/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxiedRequests *int32) (*git.AuthOptions, cleanupFunc) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// We shouldn't hit the proxy so we just want to check for any interaction, then reject.
					atomic.AddInt32(proxiedRequests, 1)
					return goproxy.RejectConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				return nil, func() {}
			},
			shortTimeout:  true,
			wantUsedProxy: false,
			wantError:     true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Run a proxy server.
			proxy := goproxy.NewProxyHttpServer()
			proxy.Verbose = true

			proxiedRequests := int32(0)
			authOpts, cleanup := tt.setupGitProxy(g, proxy, &proxiedRequests)
			defer cleanup()

			proxyServer := http.Server{
				Addr:    proxyAddr,
				Handler: proxy,
			}
			l, err := net.Listen("tcp", proxyServer.Addr)
			g.Expect(err).ToNot(HaveOccurred())
			go proxyServer.Serve(l)
			defer proxyServer.Close()

			// Set the proxy env vars for both HTTP and HTTPS because go-git caches them.
			os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://smth:else@%s", proxyAddr))
			defer os.Unsetenv("HTTPS_PROXY")

			os.Setenv("HTTP_PROXY", fmt.Sprintf("http://smth:else@%s", proxyAddr))
			defer os.Unsetenv("HTTP_PROXY")

			os.Setenv("NO_PROXY", "*.0.2.1")
			defer os.Unsetenv("NO_PROXY")

			// Checkout the repo.
			checkoutStrategy, err := strategy.CheckoutStrategyForImplementation(context.TODO(), tt.gitImpl, git.CheckoutOptions{
				Branch: tt.branch,
			})
			g.Expect(err).ToNot(HaveOccurred())

			tmpDir := t.TempDir()

			// for the NO_PROXY test we dont want to wait the 30s for it to timeout/fail, so shorten the timeout
			checkoutCtx := context.TODO()
			if tt.shortTimeout {
				var cancel context.CancelFunc
				checkoutCtx, cancel = context.WithTimeout(context.TODO(), 1*time.Second)
				defer cancel()
			}

			_, err = checkoutStrategy.Checkout(checkoutCtx, tmpDir, tt.url, authOpts)
			if tt.wantError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}

			g.Expect(atomic.LoadInt32(&proxiedRequests) > 0).To(Equal(tt.wantUsedProxy))

		})
	}
}
