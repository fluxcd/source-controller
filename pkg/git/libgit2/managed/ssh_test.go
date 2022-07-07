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
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/source-controller/pkg/git"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/pkg/gittestserver"
	git2go "github.com/libgit2/git2go/v33"
)

func TestSSHAction_clientConfig(t *testing.T) {
	kp, err := ssh.GenerateKeyPair(ssh.RSA_4096)
	if err != nil {
		t.Fatalf("could not generate keypair: %s", err)
	}
	tests := []struct {
		name             string
		authOpts         *git.AuthOptions
		expectedUsername string
		expectedAuthLen  int
		expectErr        string
	}{
		{
			name:      "nil SSHTransportOptions returns an error",
			authOpts:  nil,
			expectErr: "cannot create ssh client config from nil ssh auth options",
		},
		{
			name: "valid SSHTransportOptions returns a valid SSHClientConfig",
			authOpts: &git.AuthOptions{
				Identity: kp.PrivateKey,
				Username: "user",
			},
			expectedUsername: "user",
			expectedAuthLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			cfg, err := createClientConfig(tt.authOpts)
			if tt.expectErr != "" {
				g.Expect(tt.expectErr).To(Equal(err.Error()))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cfg.User).To(Equal(tt.expectedUsername))
			g.Expect(len(cfg.Auth)).To(Equal(tt.expectedAuthLen))
		})
	}
}

func TestSSH_E2E(t *testing.T) {
	g := NewWithT(t)

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(server.Root())

	server.KeyDir(filepath.Join(server.Root(), "keys"))

	err = server.ListenSSH()
	g.Expect(err).ToNot(HaveOccurred())

	go func() {
		server.StartSSH()
	}()
	defer server.StopSSH()

	kp, err := ssh.NewEd25519Generator().Generate()
	g.Expect(err).ToNot(HaveOccurred())

	repoPath := "test.git"
	err = server.InitRepo("../../testdata/git/repo", git.DefaultBranch, repoPath)
	g.Expect(err).ToNot(HaveOccurred())

	u, err := url.Parse(server.SSHAddress())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(u.Host).ToNot(BeEmpty())
	knownhosts, err := ssh.ScanHostKey(u.Host, 5*time.Second, git.HostKeyAlgos, false)
	g.Expect(err).NotTo(HaveOccurred())

	transportOptsURL := "ssh://git@fake-url"
	sshAddress := server.SSHAddress() + "/" + repoPath
	AddTransportOptions(transportOptsURL, TransportOptions{
		TargetURL: sshAddress,
		AuthOpts: &git.AuthOptions{
			Username:   "user",
			Identity:   kp.PrivateKey,
			KnownHosts: knownhosts,
		},
	})

	tmpDir := t.TempDir()

	// We call git2go.Clone with transportOptsURL, so that the managed ssh transport can
	// fetch the correct set of credentials and the actual target url as well.
	repo, err := git2go.Clone(transportOptsURL, tmpDir, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{
			RemoteCallbacks: RemoteCallbacks(),
		},
		CheckoutOptions: git2go.CheckoutOptions{
			Strategy: git2go.CheckoutForce,
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	repo.Free()
}
