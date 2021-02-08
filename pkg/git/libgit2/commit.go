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
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"

	git2go "github.com/libgit2/git2go/v31"
	corev1 "k8s.io/api/core/v1"
)

type Commit struct {
	commit *git2go.Commit
}

func (c *Commit) Hash() string {
	return c.commit.Id().String()
}

// Verify returns an error if the PGP signature can't be verified
func (c *Commit) Verify(secret corev1.Secret) error {
	signature, signedData, err := c.commit.ExtractSignature()
	if err != nil {
		return err
	}

	var verified bool
	for _, b := range secret.Data {
		keyRingReader := strings.NewReader(string(b))
		keyring, err := openpgp.ReadArmoredKeyRing(keyRingReader)
		if err != nil {
			return err
		}

		_, err = openpgp.CheckArmoredDetachedSignature(keyring, strings.NewReader(signedData), bytes.NewBufferString(signature))
		if err == nil {
			verified = true
			break
		}
	}

	if !verified {
		return fmt.Errorf("PGP signature '%s' of '%s' can't be verified", signature, c.commit.Committer().Email)
	}

	return nil
}
