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
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/ssh"

	git2go "github.com/libgit2/git2go/v31"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/source-controller/pkg/git/common"
)

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
	var credCallback git2go.CredentialsCallback
	var username string
	if d, ok := secret.Data["username"]; ok {
		username = string(d)
	}
	var password string
	if d, ok := secret.Data["password"]; ok {
		password = string(d)
	}
	if username != "" && password != "" {
		credCallback = func(url string, username_from_url string, allowed_types git2go.CredType) (*git2go.Cred, error) {
			cred, err := git2go.NewCredUserpassPlaintext(username, password)
			if err != nil {
				return nil, err
			}
			return cred, nil
		}
	}

	var certCallback git2go.CertificateCheckCallback
	if caFile, ok := secret.Data[common.CAFile]; ok {
		certCallback = func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
			roots := x509.NewCertPool()
			ok := roots.AppendCertsFromPEM(caFile)
			if !ok {
				return git2go.ErrCertificate
			}

			opts := x509.VerifyOptions{
				Roots:   roots,
				DNSName: hostname,
			}
			_, err := cert.X509.Verify(opts)
			if err != nil {
				return git2go.ErrCertificate
			}
			return git2go.ErrOk
		}
	}

	return &common.Auth{CredCallback: credCallback, CertCallback: certCallback}, nil
}

type PublicKeyAuth struct {
	user string
}

func (s *PublicKeyAuth) Method(secret corev1.Secret) (*common.Auth, error) {
	if _, ok := secret.Data[common.CAFile]; ok {
		return nil, fmt.Errorf("found caFile key in secret '%s' but libgit2 SSH transport does not support custom certificates", secret.Name)
	}

	identity := secret.Data["identity"]
	knownHosts := secret.Data["known_hosts"]
	if len(identity) == 0 || len(knownHosts) == 0 {
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'identity' and 'known_hosts'", secret.Name)
	}

	kk, err := parseKnownHosts(string(knownHosts))
	if err != nil {
		return nil, err
	}

	// Need to validate private key as it is not
	// done by git2go when loading the key
	_, err = ssh.ParsePrivateKey(identity)
	if err != nil {
		return nil, err
	}

	user := s.user
	if user == "" {
		user = common.DefaultPublicKeyAuthUser
	}

	credCallback := func(url string, username_from_url string, allowed_types git2go.CredType) (*git2go.Cred, error) {
		cred, err := git2go.NewCredSshKeyFromMemory(user, "", string(identity), "")
		if err != nil {
			return nil, err
		}
		return cred, nil
	}
	certCallback := func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		for _, k := range kk {
			if k.matches(hostname, cert.Hostkey.HashSHA1[:]) {
				return git2go.ErrOk
			}
		}
		return git2go.ErrGeneric
	}

	return &common.Auth{CredCallback: credCallback, CertCallback: certCallback}, nil
}

type knownKey struct {
	hosts []string
	key   ssh.PublicKey
}

func parseKnownHosts(s string) ([]knownKey, error) {
	knownHosts := []knownKey{}
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		_, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			return []knownKey{}, err
		}

		knownHost := knownKey{
			hosts: hosts,
			key:   pubKey,
		}
		knownHosts = append(knownHosts, knownHost)
	}

	if err := scanner.Err(); err != nil {
		return []knownKey{}, err
	}

	return knownHosts, nil
}

func (k knownKey) matches(host string, key []byte) bool {
	if !containsHost(k.hosts, host) {
		return false
	}

	hash := sha1.Sum([]byte(k.key.Marshal()))
	if bytes.Compare(hash[:], key) != 0 {
		return false
	}

	return true
}

func containsHost(hosts []string, host string) bool {
	for _, h := range hosts {
		if h == host {
			return true
		}
	}

	return false
}
