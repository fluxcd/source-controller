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

package fake

import (
	"errors"

	corev1 "k8s.io/api/core/v1"
)

type Commit struct {
	valid bool
	hash  string
}

func NewCommit(valid bool, hash string) Commit {
	return Commit{
		valid: valid,
		hash:  hash,
	}
}

func (c Commit) Verify(secret corev1.Secret) error {
	if !c.valid {
		return errors.New("invalid signature")
	}
	return nil
}

func (c Commit) Hash() string {
	return c.hash
}
