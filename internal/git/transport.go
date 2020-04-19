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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	corev1 "k8s.io/api/core/v1"
)

func AuthMethodFromSecret(url string, secret corev1.Secret) (transport.AuthMethod, func(), error) {
	switch {
	case strings.HasPrefix(url, "http"):
		auth, err := BasicAuthFromSecret(secret)
		return auth, nil, err
	case strings.HasPrefix(url, "ssh"):
		return PublicKeysFromSecret(secret)
	}
	return nil, nil, nil
}

func BasicAuthFromSecret(secret corev1.Secret) (*http.BasicAuth, error) {
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

func PublicKeysFromSecret(secret corev1.Secret) (*ssh.PublicKeys, func(), error) {
	identity := secret.Data["identity"]
	knownHosts := secret.Data["known_hosts"]
	if len(identity) == 0 || len(knownHosts) == 0 {
		return nil, nil, fmt.Errorf("invalid '%s' secret data: required fields 'identity' and 'known_hosts'", secret.Name)
	}

	pk, err := ssh.NewPublicKeys("git", identity, "")
	if err != nil {
		return nil, nil, err
	}

	// create tmp dir for known_hosts
	tmp, err := ioutil.TempDir("", "ssh-"+secret.Name)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(tmp) }

	knownHostsPath := filepath.Join(tmp, "known_hosts")
	if err := ioutil.WriteFile(knownHostsPath, knownHosts, 0644); err != nil {
		cleanup()
		return nil, nil, err
	}

	callback, err := ssh.NewKnownHostsCallback(knownHostsPath)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	pk.HostKeyCallback = callback
	return pk, cleanup, nil
}
