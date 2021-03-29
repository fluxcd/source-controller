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

package git

import (
	"context"

	"github.com/go-git/go-git/v5/plumbing/transport"
	git2go "github.com/libgit2/git2go/v31"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultOrigin            = "origin"
	DefaultBranch            = "master"
	DefaultPublicKeyAuthUser = "git"
	CAFile                   = "caFile"
)

type Commit interface {
	Verify(secret corev1.Secret) error
	Hash() string
}

type CheckoutStrategy interface {
	Checkout(ctx context.Context, path, url string, auth *Auth) (Commit, string, error)
}

type CheckoutOptions struct {
	GitImplementation string
	RecurseSubmodules bool
}

// TODO(hidde): candidate for refactoring, so that we do not directly
//  depend on implementation specifics here.
type Auth struct {
	AuthMethod   transport.AuthMethod
	CABundle     []byte
	CredCallback git2go.CredentialsCallback
	CertCallback git2go.CertificateCheckCallback
}

type AuthSecretStrategy interface {
	Method(secret corev1.Secret) (*Auth, error)
}
