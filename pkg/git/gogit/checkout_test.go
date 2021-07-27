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
	"os"
	"testing"

	"github.com/fluxcd/source-controller/pkg/git"
)

func TestCheckoutTagSemVer_Checkout(t *testing.T) {
	auth := &git.Auth{}
	tag := CheckoutTag{
		tag: "v1.7.0",
	}
	tmpDir, _ := os.MkdirTemp("", "test")
	defer os.RemoveAll(tmpDir)

	cTag, _, err := tag.Checkout(context.TODO(), tmpDir, "https://github.com/projectcontour/contour", auth)
	if err != nil {
		t.Error(err)
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
