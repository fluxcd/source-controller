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
	"fmt"
	"net/url"

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/pkg/ssh/knownhosts"

	"github.com/fluxcd/source-controller/pkg/git"
)

func AuthSecretStrategyForURL(URL string) (git.AuthSecretStrategy, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL to determine auth strategy: %w", err)
	}

	switch {
	case u.Scheme == "http", u.Scheme == "https":
		return &BasicAuth{}, nil
	case u.Scheme == "ssh":
		return &PublicKeyAuth{user: u.User.Username()}, nil
	default:
		return nil, fmt.Errorf("no auth secret strategy for scheme %s", u.Scheme)
	}
}

type BasicAuth struct{}

func (s *BasicAuth) Method(secret corev1.Secret) (*git.Auth, error) {
	auth := &git.Auth{}
	basicAuth := &http.BasicAuth{}

	if caBundle, ok := secret.Data[git.CAFile]; ok {
		auth.CABundle = caBundle
	}
	if username, ok := secret.Data["username"]; ok {
		basicAuth.Username = string(username)
	}
	if password, ok := secret.Data["password"]; ok {
		basicAuth.Password = string(password)
	}
	if (basicAuth.Username == "" && basicAuth.Password != "") || (basicAuth.Username != "" && basicAuth.Password == "") {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	if basicAuth.Username != "" && basicAuth.Password != "" {
		auth.AuthMethod = basicAuth
	}
	return auth, nil
}

type PublicKeyAuth struct {
	user string
}

func (s *PublicKeyAuth) Method(secret corev1.Secret) (*git.Auth, error) {
	if _, ok := secret.Data[git.CAFile]; ok {
		return nil, fmt.Errorf("found caFile key in secret '%s' but go-git SSH transport does not support custom certificates", secret.Name)
	}
	identity := secret.Data["identity"]
	knownHosts := secret.Data["known_hosts"]
	if len(identity) == 0 || len(knownHosts) == 0 {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'identity' and 'known_hosts'", secret.Name)
	}

	user := s.user
	if user == "" {
		user = git.DefaultPublicKeyAuthUser
	}

	password := secret.Data["password"]
	pk, err := ssh.NewPublicKeys(user, identity, string(password))
	if err != nil {
		return nil, err
	}

	callback, err := knownhosts.New(knownHosts)
	if err != nil {
		return nil, err
	}
	pk.HostKeyCallback = callback
	return &git.Auth{AuthMethod: pk}, nil
}
