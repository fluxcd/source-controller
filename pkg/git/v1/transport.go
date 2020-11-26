/*
Copyright 2020 The Flux CD contributors.

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
	"net/url"

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/pkg/ssh/knownhosts"
	"github.com/fluxcd/source-controller/pkg/git/common"
)

const defaultPublicKeyAuthUser = "git"

func AuthSecretStrategyForURL(URL string) (common.AuthSecretStrategy, error) {
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

func (s *BasicAuth) Method(secret corev1.Secret) (*common.Auth, error) {
	auth := &http.BasicAuth{}
	if username, ok := secret.Data["username"]; ok {
		auth.Username = string(username)
	}
	if password, ok := secret.Data["password"]; ok {
		auth.Password = string(password)
	}
	if auth.Username == "" || auth.Password == "" {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	return &common.Auth{AuthMethod: auth}, nil
}

type PublicKeyAuth struct {
	user string
}

func (s *PublicKeyAuth) Method(secret corev1.Secret) (*common.Auth, error) {
	identity := secret.Data["identity"]
	knownHosts := secret.Data["known_hosts"]
	if len(identity) == 0 || len(knownHosts) == 0 {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'identity' and 'known_hosts'", secret.Name)
	}

	user := s.user
	if user == "" {
		user = defaultPublicKeyAuthUser
	}

	pk, err := ssh.NewPublicKeys(user, identity, "")
	if err != nil {
		return nil, err
	}

	callback, err := knownhosts.New(knownHosts)
	if err != nil {
		return nil, err
	}
	pk.HostKeyCallback = callback
	return &common.Auth{AuthMethod: pk}, nil
}
