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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	git2go "github.com/libgit2/git2go/v31"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/source-controller/pkg/git"
)

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	certCallback := func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		return 0
	}
	auth := &git.Auth{CertCallback: certCallback}

	tag := CheckoutTag{
		tag: "v1.7.0",
	}
	tmpDir, _ := os.MkdirTemp("", "test")
	defer os.RemoveAll(tmpDir)

	cTag, _, err := tag.Checkout(context.TODO(), tmpDir, "https://github.com/projectcontour/contour", auth)
	if err != nil {
		t.Error(err)
	}

	// Ensure the correct files are checked out on disk
	f, err := os.Open(path.Join(tmpDir, "README.md"))
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Error(err)
	}
	fileHash := hex.EncodeToString(h.Sum(nil))
	if fileHash != "2bd1707542a11f987ee24698dcc095a9f57639f401133ef6a29da97bf8f3f302" {
		t.Errorf("expected files not checked out. Expected hash %s, got %s", "2bd1707542a11f987ee24698dcc095a9f57639f401133ef6a29da97bf8f3f302", fileHash)
	}

	semVer := CheckoutSemVer{
		semVer: ">=1.0.0 <=1.7.0",
	}
	tmpDir2, _ := os.MkdirTemp("", "test")
	defer os.RemoveAll(tmpDir2)

	cSemVer, _, err := semVer.Checkout(context.TODO(), tmpDir2, "https://github.com/projectcontour/contour", auth)
	if err != nil {
		t.Error(err)
	}

	if cTag.Hash() != cSemVer.Hash() {
		t.Errorf("expected semver hash %s, got %s", cTag.Hash(), cSemVer.Hash())
	}
}

// This test is specifically to detect regression in libgit2's ED25519 key
// support.
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

	err = server.InitRepo("testdata/git/repo", git.DefaultBranch, repoPath)
	g.Expect(err).NotTo(HaveOccurred())

	sshURL := server.SSHAddress()
	repoURL := sshURL + "/" + repoPath

	// Fetch host key.
	u, err := url.Parse(sshURL)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(u.Host).ToNot(BeEmpty())
	knownHosts, err := ssh.ScanHostKey(u.Host, timeout)
	g.Expect(err).ToNot(HaveOccurred())

	kp, err := ssh.NewEd25519Generator().Generate()
	g.Expect(err).ToNot(HaveOccurred())

	secret := corev1.Secret{
		Data: map[string][]byte{
			"identity":    kp.PrivateKey,
			"known_hosts": knownHosts,
		},
	}

	authStrategy, err := AuthSecretStrategyForURL(repoURL)
	g.Expect(err).ToNot(HaveOccurred())
	gitAuth, err := authStrategy.Method(secret)
	g.Expect(err).ToNot(HaveOccurred())

	// Prepare for checkout.
	branchCheckoutStrat := &CheckoutBranch{branch: git.DefaultBranch}
	tmpDir, _ := os.MkdirTemp("", "test")
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	// Checkout the repo.
	// This should always fail because the generated key above isn't present in
	// the git server.
	_, _, err = branchCheckoutStrat.Checkout(ctx, tmpDir, repoURL, gitAuth)
	g.Expect(err).To(HaveOccurred())
	// NOTE: libgit2 v1.2+ supports ED25519. Flip this condition after updating
	// to libgit2 v1.2+.
	g.Expect(err.Error()).To(ContainSubstring("Unable to extract public key from private key"))
}
