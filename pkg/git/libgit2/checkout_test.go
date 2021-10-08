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
	"os"
	"path"
	"testing"

	git2go "github.com/libgit2/git2go/v31"

	"github.com/fluxcd/source-controller/pkg/git"
)

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	certCallback := func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		return git2go.ErrorCodeOK
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
	const expectedHash = "2bd1707542a11f987ee24698dcc095a9f57639f401133ef6a29da97bf8f3f302"
	fileHash := hex.EncodeToString(h.Sum(nil))
	if fileHash != expectedHash {
		t.Errorf("expected files not checked out. Expected hash %s, got %s", expectedHash, fileHash)
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
