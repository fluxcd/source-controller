/*
Copyright 2022 The Flux authors

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

package managed

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/source-controller/pkg/git"
	. "github.com/onsi/gomega"

	git2go "github.com/libgit2/git2go/v33"
)

func TestMain(m *testing.M) {
	err := InitManagedTransport()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize libgit2 managed transport: %s", err))
	}
	code := m.Run()
	os.Exit(code)
}

func TestHttpAction_CreateClientRequest(t *testing.T) {
	authOpts := git.AuthOptions{
		Username: "user",
		Password: "pwd",
	}
	url := "https://final-target/abc"

	tests := []struct {
		name       string
		assertFunc func(g *WithT, req *http.Request, client *http.Client)
		action     git2go.SmartServiceAction
		authOpts   git.AuthOptions
		transport  *http.Transport
		wantedErr  error
	}{
		{
			name:   "Uploadpack: URL, method and headers are correctly set",
			action: git2go.SmartServiceActionUploadpack,
			transport: &http.Transport{
				Proxy:              http.ProxyFromEnvironment,
				ProxyConnectHeader: map[string][]string{},
			},
			assertFunc: func(g *WithT, req *http.Request, _ *http.Client) {
				g.Expect(req.URL.String()).To(Equal("https://final-target/abc/git-upload-pack"))
				g.Expect(req.Method).To(Equal("POST"))
				g.Expect(req.Header).To(BeEquivalentTo(map[string][]string{
					"User-Agent":   {"git/2.0 (flux-libgit2)"},
					"Content-Type": {"application/x-git-upload-pack-request"},
				}))
			},
			wantedErr: nil,
		},
		{
			name:      "UploadpackLs: URL, method and headers are correctly set",
			action:    git2go.SmartServiceActionUploadpackLs,
			transport: &http.Transport{},
			assertFunc: func(g *WithT, req *http.Request, _ *http.Client) {
				g.Expect(req.URL.String()).To(Equal("https://final-target/abc/info/refs?service=git-upload-pack"))
				g.Expect(req.Method).To(Equal("GET"))
				g.Expect(req.Header).To(BeEquivalentTo(map[string][]string{
					"User-Agent": {"git/2.0 (flux-libgit2)"},
				}))
			},
			wantedErr: nil,
		},
		{
			name:   "Receivepack: URL, method and headers are correctly set",
			action: git2go.SmartServiceActionReceivepack,
			transport: &http.Transport{
				Proxy:              http.ProxyFromEnvironment,
				ProxyConnectHeader: map[string][]string{},
			},
			assertFunc: func(g *WithT, req *http.Request, _ *http.Client) {
				g.Expect(req.URL.String()).To(Equal("https://final-target/abc/git-receive-pack"))
				g.Expect(req.Method).To(Equal("POST"))
				g.Expect(req.Header).To(BeEquivalentTo(map[string][]string{
					"Content-Type": {"application/x-git-receive-pack-request"},
					"User-Agent":   {"git/2.0 (flux-libgit2)"},
				}))
			},
			wantedErr: nil,
		},
		{
			name:      "ReceivepackLs: URL, method and headars are correctly set",
			action:    git2go.SmartServiceActionReceivepackLs,
			transport: &http.Transport{},
			assertFunc: func(g *WithT, req *http.Request, _ *http.Client) {
				g.Expect(req.URL.String()).To(Equal("https://final-target/abc/info/refs?service=git-receive-pack"))
				g.Expect(req.Method).To(Equal("GET"))
				g.Expect(req.Header).To(BeEquivalentTo(map[string][]string{
					"User-Agent": {"git/2.0 (flux-libgit2)"},
				}))
			},
			wantedErr: nil,
		},
		{
			name:      "incomplete credentials, no basic auth",
			action:    git2go.SmartServiceActionReceivepackLs,
			transport: &http.Transport{},
			authOpts:  git.AuthOptions{Username: "user"},
			assertFunc: func(g *WithT, req *http.Request, client *http.Client) {
				_, _, ok := req.BasicAuth()
				g.Expect(ok).To(BeFalse())
			},
		},
		{
			name:   "credentials are correctly configured",
			action: git2go.SmartServiceActionUploadpack,
			transport: &http.Transport{
				Proxy:              http.ProxyFromEnvironment,
				ProxyConnectHeader: map[string][]string{},
			},
			authOpts: authOpts,
			assertFunc: func(g *WithT, req *http.Request, client *http.Client) {
				g.Expect(req.URL.String()).To(Equal("https://final-target/abc/git-upload-pack"))
				g.Expect(req.Method).To(Equal("POST"))

				username, pwd, ok := req.BasicAuth()
				if !ok {
					t.Errorf("could not find Authentication header in request.")
				}
				g.Expect(username).To(Equal("user"))
				g.Expect(pwd).To(Equal("pwd"))
			},
			wantedErr: nil,
		},
		{
			name:      "error when no http.transport provided",
			action:    git2go.SmartServiceActionUploadpack,
			transport: nil,
			wantedErr: fmt.Errorf("failed to create client: transport cannot be nil"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			client, req, err := createClientRequest(url, tt.action, tt.transport, &tt.authOpts)
			if err != nil {
				t.Log(err)
			}
			if tt.wantedErr != nil {
				g.Expect(err).To(Equal(tt.wantedErr))
			} else {
				tt.assertFunc(g, req, client)
			}

		})
	}
}

func TestHTTP_E2E(t *testing.T) {
	g := NewWithT(t)

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(server.Root())

	user := "test-user"
	pwd := "test-pswd"
	server.Auth(user, pwd)
	server.KeyDir(filepath.Join(server.Root(), "keys"))

	err = server.StartHTTP()
	g.Expect(err).ToNot(HaveOccurred())
	defer server.StopHTTP()

	repoPath := "test.git"
	err = server.InitRepo("../../testdata/git/repo", git.DefaultBranch, repoPath)
	g.Expect(err).ToNot(HaveOccurred())

	tmpDir := t.TempDir()

	// Register the auth options and target url mapped to a unique url.
	id := "http://obj-id"
	AddTransportOptions(id, TransportOptions{
		TargetURL: server.HTTPAddress() + "/" + repoPath,
		AuthOpts: &git.AuthOptions{
			Username: user,
			Password: pwd,
		},
	})

	// We call git2go.Clone with transportOptsURL instead of the actual URL,
	// as the transport action will fetch the actual URL and the required
	// credentials using the it as an identifier.
	repo, err := git2go.Clone(id, tmpDir, &git2go.CloneOptions{
		CheckoutOptions: git2go.CheckoutOptions{
			Strategy: git2go.CheckoutForce,
		},
	})
	g.Expect(err).ToNot(HaveOccurred())
	repo.Free()
}

func TestTrimActionSuffix(t *testing.T) {
	tests := []struct {
		name    string
		inURL   string
		wantURL string
	}{
		{
			name:    "ignore other suffixes",
			inURL:   "https://gitlab/repo/podinfo.git/somethingelse",
			wantURL: "https://gitlab/repo/podinfo.git/somethingelse",
		},
		{
			name:    "trim /info/refs?service=git-upload-pack",
			inURL:   "https://gitlab/repo/podinfo.git/info/refs?service=git-upload-pack",
			wantURL: "https://gitlab/repo/podinfo.git",
		},
		{
			name:    "trim /git-upload-pack",
			inURL:   "https://gitlab/repo/podinfo.git/git-upload-pack",
			wantURL: "https://gitlab/repo/podinfo.git",
		},
		{
			name:    "trim /info/refs?service=git-receive-pack",
			inURL:   "https://gitlab/repo/podinfo.git/info/refs?service=git-receive-pack",
			wantURL: "https://gitlab/repo/podinfo.git",
		},
		{
			name:    "trim /git-receive-pack",
			inURL:   "https://gitlab/repo/podinfo.git/git-receive-pack",
			wantURL: "https://gitlab/repo/podinfo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			gotURL := trimActionSuffix(tt.inURL)
			g.Expect(gotURL).To(Equal(tt.wantURL))
		})
	}
}

func TestHTTP_HandleRedirect(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
	}{
		{name: "http to https", repoURL: "http://github.com/stefanprodan/podinfo"},
		{name: "handle gitlab redirect", repoURL: "https://gitlab.com/stefanprodan/podinfo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tmpDir := t.TempDir()

			id := "http://obj-id"
			AddTransportOptions(id, TransportOptions{
				TargetURL: tt.repoURL,
			})

			// GitHub will cause a 301 and redirect to https
			repo, err := git2go.Clone(id, tmpDir, &git2go.CloneOptions{
				CheckoutOptions: git2go.CheckoutOptions{
					Strategy: git2go.CheckoutForce,
				},
			})

			g.Expect(err).ToNot(HaveOccurred())
			repo.Free()
		})
	}
}
