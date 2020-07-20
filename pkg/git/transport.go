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

package git

import (
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/pkg/ssh/knownhosts"
)

func AuthSecretStrategyForURL(url string) AuthSecretStrategy {
	switch {
	case strings.HasPrefix(url, "http"):
		return &BasicAuth{}
	case strings.HasPrefix(url, "ssh"):
		return &PublicKeyAuth{}
	}
	return nil
}

type AuthSecretStrategy interface {
	Method(secret corev1.Secret) (transport.AuthMethod, error)
}

type BasicAuth struct{}

func (s *BasicAuth) Method(secret corev1.Secret) (transport.AuthMethod, error) {
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
	return auth, nil
}

type PublicKeyAuth struct{}

func (s *PublicKeyAuth) Method(secret corev1.Secret) (transport.AuthMethod, error) {
	identity := secret.Data["identity"]
	knownHosts := secret.Data["known_hosts"]
	if len(identity) == 0 || len(knownHosts) == 0 {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'identity' and 'known_hosts'", secret.Name)
	}

	pk, err := ssh.NewPublicKeys("git", identity, "")
	if err != nil {
		return nil, err
	}

	callback, err := knownhosts.New(knownHosts)
	if err != nil {
		return nil, err
	}
	pk.HostKeyCallback = callback
	return pk, nil
}
