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

package v1

import (
	"fmt"

	"github.com/go-git/go-git/v5/plumbing/object"
	corev1 "k8s.io/api/core/v1"
)

type Commit struct {
	commit *object.Commit
}

func (c *Commit) Hash() string {
	return ""
}

// Verify returns an error if the PGP signature can't be verified
func (c *Commit) Verify(secret corev1.Secret) error {
	if c.commit.PGPSignature == "" {
		return fmt.Errorf("no PGP signature found for commit: %s", c.commit.Hash)
	}

	var verified bool
	for _, bytes := range secret.Data {
		if _, err := c.commit.Verify(string(bytes)); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("PGP signature '%s' of '%s' can't be verified", c.commit.PGPSignature, c.commit.Author)
	}
	return nil
}
