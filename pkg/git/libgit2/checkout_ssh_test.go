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

package libgit2

import (
	"context"
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

	. "github.com/onsi/gomega"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/fluxcd/source-controller/pkg/git"
)

const testRepositoryPath = "../testdata/git/repo"

// Test_ssh_keyTypes assures support for the different
// types of keys for SSH Authentication supported by Flux.
func Test_ssh_keyTypes(t *testing.T) {
	tests := []struct {
		name       string
		keyType    ssh.KeyPairType
		authorized bool
		wantErr    string
	}{
		{
			name:       "RSA 4096",
			keyType:    ssh.RSA_4096,
			authorized: true,
		},
		{
			name:       "ECDSA P256",
			keyType:    ssh.ECDSA_P256,
			authorized: true,
		},
		{
			name:       "ECDSA P384",
			keyType:    ssh.ECDSA_P384,
			authorized: true,
		},
		{
			name:       "ECDSA P521",
			keyType:    ssh.ECDSA_P521,
			authorized: true,
		},
		{
			name:       "ED25519",
			keyType:    ssh.ED25519,
			authorized: true,
		},
		{
			name:    "unauthorized key",
			keyType: ssh.RSA_4096,
			wantErr: "unable to authenticate, attempted methods [none publickey], no supported methods remain",
		},
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

			authOpts := &git.AuthOptions{
				Identity:   kp.PrivateKey,
				KnownHosts: knownHosts,
			}
			authOpts.TransportOptionsURL = getTransportOptionsURL(git.SSH)

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

// Test_ssh_keyExchangeAlgos assures support for the different
// types of SSH key exchange algorithms supported by Flux.
func Test_ssh_keyExchangeAlgos(t *testing.T) {
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

			authOpts := &git.AuthOptions{
				Identity:   kp.PrivateKey,
				KnownHosts: knownHosts,
			}
			authOpts.TransportOptionsURL = getTransportOptionsURL(git.SSH)

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

// Test_ssh_hostKeyAlgos assures support for the different
// types of SSH Host Key algorithms supported by Flux.
func Test_ssh_hostKeyAlgos(t *testing.T) {
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

			knownHosts, err := ssh.ScanHostKey(u.Host, timeout, tt.ClientHostKeyAlgos, tt.hashHostNames)
			g.Expect(err).ToNot(HaveOccurred())

			// No authentication is required for this test, but it is
			// used here to make the Checkout logic happy.
			kp, err := ssh.GenerateKeyPair(ssh.ED25519)
			g.Expect(err).ToNot(HaveOccurred())

			authOpts := &git.AuthOptions{
				Identity:   kp.PrivateKey,
				KnownHosts: knownHosts,
			}
			authOpts.TransportOptionsURL = getTransportOptionsURL(git.SSH)

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
