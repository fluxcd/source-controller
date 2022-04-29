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
	"reflect"
	"testing"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/go-logr/logr"

	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
	"gotest.tools/assert"
)

func TestHttpAction_CreateClientRequest(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		expectedUrl    string
		expectedMethod string
		action         git2go.SmartServiceAction
		opts           *TransportOptions
		transport      *http.Transport
		wantedErr      error
	}{
		{
			name:           "Uploadpack: no changes when no options found",
			url:            "https://sometarget/abc",
			expectedUrl:    "https://sometarget/abc/git-upload-pack",
			expectedMethod: "POST",
			action:         git2go.SmartServiceActionUploadpack,
			transport:      &http.Transport{},
			opts:           nil,
			wantedErr:      nil,
		},
		{
			name:           "UploadpackLs: no changes when no options found",
			url:            "https://sometarget/abc",
			expectedUrl:    "https://sometarget/abc/info/refs?service=git-upload-pack",
			expectedMethod: "GET",
			action:         git2go.SmartServiceActionUploadpackLs,
			transport:      &http.Transport{},
			opts:           nil,
			wantedErr:      nil,
		},
		{
			name:           "Receivepack: no changes when no options found",
			url:            "https://sometarget/abc",
			expectedUrl:    "https://sometarget/abc/git-receive-pack",
			expectedMethod: "POST",
			action:         git2go.SmartServiceActionReceivepack,
			transport:      &http.Transport{},
			opts:           nil,
			wantedErr:      nil,
		},
		{
			name:           "ReceivepackLs: no changes when no options found",
			url:            "https://sometarget/abc",
			expectedUrl:    "https://sometarget/abc/info/refs?service=git-receive-pack",
			expectedMethod: "GET",
			action:         git2go.SmartServiceActionReceivepackLs,
			transport:      &http.Transport{},
			opts:           nil,
			wantedErr:      nil,
		},
		{
			name:           "override URL via options",
			url:            "https://initial-target/abc",
			expectedUrl:    "https://final-target/git-upload-pack",
			expectedMethod: "POST",
			action:         git2go.SmartServiceActionUploadpack,
			transport:      &http.Transport{},
			opts: &TransportOptions{
				TargetURL: "https://final-target",
			},
			wantedErr: nil,
		},
		{
			name:           "error when no http.transport provided",
			url:            "https://initial-target/abc",
			expectedUrl:    "",
			expectedMethod: "",
			action:         git2go.SmartServiceActionUploadpack,
			transport:      nil,
			opts:           nil,
			wantedErr:      fmt.Errorf("failed to create client: transport cannot be nil"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				AddTransportOptions(tt.url, *tt.opts)
			}

			_, req, err := createClientRequest(tt.url, tt.action, tt.transport)
			if tt.wantedErr != nil {
				if tt.wantedErr.Error() != err.Error() {
					t.Errorf("wanted: %v got: %v", tt.wantedErr, err)
				}
			} else {
				assert.Equal(t, req.URL.String(), tt.expectedUrl)
				assert.Equal(t, req.Method, tt.expectedMethod)
			}

			if tt.opts != nil {
				RemoveTransportOptions(tt.url)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	tests := []struct {
		name         string
		registerOpts bool
		url          string
		opts         TransportOptions
		expectOpts   bool
		expectedOpts *TransportOptions
	}{
		{
			name:         "return registered option",
			registerOpts: true,
			url:          "https://target/?123",
			opts:         TransportOptions{},
			expectOpts:   true,
			expectedOpts: &TransportOptions{},
		},
		{
			name:         "match registered options",
			registerOpts: true,
			url:          "https://target/?876",
			opts: TransportOptions{
				TargetURL: "https://new-target/321",
				CABundle:  []byte{123, 213, 132},
			},
			expectOpts: true,
			expectedOpts: &TransportOptions{
				TargetURL: "https://new-target/321",
				CABundle:  []byte{123, 213, 132},
			},
		},
		{
			name:         "ignore when options not registered",
			registerOpts: false,
			url:          "",
			opts:         TransportOptions{},
			expectOpts:   false,
			expectedOpts: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.registerOpts {
				AddTransportOptions(tt.url, tt.opts)
			}

			opts, found := transportOptions(tt.url)
			if tt.expectOpts != found {
				t.Errorf("%s: wanted %v got %v", tt.name, tt.expectOpts, found)
			}

			if tt.expectOpts {
				if reflect.DeepEqual(opts, *tt.expectedOpts) {
					t.Errorf("%s: wanted %v got %v", tt.name, *tt.expectedOpts, opts)
				}
			}

			if tt.registerOpts {
				RemoveTransportOptions(tt.url)
			}

			if _, found = transportOptions(tt.url); found {
				t.Errorf("%s: option for %s was not removed", tt.name, tt.url)
			}
		})
	}
}

func TestFlagStatus(t *testing.T) {
	if Enabled() {
		t.Errorf("experimental transport should not be enabled by default")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "true")
	if !Enabled() {
		t.Errorf("experimental transport should be enabled when env EXPERIMENTAL_GIT_TRANSPORT=true")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "1")
	if !Enabled() {
		t.Errorf("experimental transport should be enabled when env EXPERIMENTAL_GIT_TRANSPORT=1")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "somethingelse")
	if Enabled() {
		t.Errorf("experimental transport should be enabled only when env EXPERIMENTAL_GIT_TRANSPORT is 1 or true but was enabled for 'somethingelse'")
	}

	os.Unsetenv("EXPERIMENTAL_GIT_TRANSPORT")
	if Enabled() {
		t.Errorf("experimental transport should not be enabled when env EXPERIMENTAL_GIT_TRANSPORT is not present")
	}
}

func TestManagedTransport_E2E(t *testing.T) {
	g := NewWithT(t)

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(server.Root())

	user := "test-user"
	pasword := "test-pswd"
	server.Auth(user, pasword)
	server.KeyDir(filepath.Join(server.Root(), "keys"))

	err = server.ListenSSH()
	g.Expect(err).ToNot(HaveOccurred())

	err = server.StartHTTP()
	g.Expect(err).ToNot(HaveOccurred())
	defer server.StopHTTP()

	go func() {
		server.StartSSH()
	}()
	defer server.StopSSH()

	// Force managed transport to be enabled
	InitManagedTransport(logr.Discard())

	repoPath := "test.git"
	err = server.InitRepo("../testdata/git/repo", git.DefaultBranch, repoPath)
	g.Expect(err).ToNot(HaveOccurred())

	tmpDir := t.TempDir()

	// Test HTTP transport

	// Use a fake-url and force it to be overriden by the smart transport.
	// This was the way found to ensure that the built-in transport was not used.
	httpAddress := "http://fake-url"
	AddTransportOptions(httpAddress, TransportOptions{
		TargetURL: server.HTTPAddress() + "/" + repoPath,
	})

	repo, err := git2go.Clone(httpAddress, tmpDir, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback: func(url, username_from_url string, allowed_types git2go.CredentialType) (*git2go.Credential, error) {
					return git2go.NewCredentialUserpassPlaintext(user, pasword)
				},
			},
		},
		CheckoutOptions: git2go.CheckoutOptions{
			Strategy: git2go.CheckoutForce,
		},
	})
	g.Expect(err).ToNot(HaveOccurred())
	repo.Free()

	tmpDir2 := t.TempDir()

	kp, err := ssh.NewEd25519Generator().Generate()
	g.Expect(err).ToNot(HaveOccurred())

	// Test SSH transport
	sshAddress := server.SSHAddress() + "/" + repoPath
	repo, err = git2go.Clone(sshAddress, tmpDir2, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback: func(url, username_from_url string, allowed_types git2go.CredentialType) (*git2go.Credential, error) {
					return git2go.NewCredentialSSHKeyFromMemory("git", "", string(kp.PrivateKey), "")
				},
			},
		},
		CheckoutOptions: git2go.CheckoutOptions{
			Strategy: git2go.CheckoutForce,
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	repo.Free()
}

func TestManagedTransport_HandleRedirect(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()

	// Force managed transport to be enabled
	InitManagedTransport(logr.Discard())

	// GitHub will cause a 301 and redirect to https
	repo, err := git2go.Clone("http://github.com/stefanprodan/podinfo", tmpDir, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{},
		CheckoutOptions: git2go.CheckoutOptions{
			Strategy: git2go.CheckoutForce,
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	repo.Free()
}
