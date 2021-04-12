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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"hash"
	"net"
	"net/url"
	"strings"

	git2go "github.com/libgit2/git2go/v31"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	corev1 "k8s.io/api/core/v1"

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
		return &PublicKeyAuth{user: u.User.Username(), host: u.Host}, nil
	default:
		return nil, fmt.Errorf("no auth secret strategy for scheme %s", u.Scheme)
	}
}

type BasicAuth struct{}

func (s *BasicAuth) Method(secret corev1.Secret) (*git.Auth, error) {
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
		credCallback = func(url string, usernameFromURL string, allowedTypes git2go.CredType) (*git2go.Cred, error) {
			cred, err := git2go.NewCredUserpassPlaintext(username, password)
			if err != nil {
				return nil, err
			}
			return cred, nil
		}
	}

	var certCallback git2go.CertificateCheckCallback
	if caFile, ok := secret.Data[git.CAFile]; ok {
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

	return &git.Auth{CredCallback: credCallback, CertCallback: certCallback}, nil
}

type PublicKeyAuth struct {
	user string
	host string
}

func (s *PublicKeyAuth) Method(secret corev1.Secret) (*git.Auth, error) {
	if _, ok := secret.Data[git.CAFile]; ok {
		return nil, fmt.Errorf("found %s key in secret '%s' but libgit2 SSH transport does not support custom certificates", git.CAFile, secret.Name)
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
	password, ok := secret.Data["password"]
	if ok {
		_, err = ssh.ParsePrivateKeyWithPassphrase(identity, password)
	} else {
		_, err = ssh.ParsePrivateKey(identity)
	}

	if err != nil {
		return nil, err
	}

	user := s.user
	if user == "" {
		user = git.DefaultPublicKeyAuthUser
	}

	credCallback := func(url string, usernameFromURL string, allowedTypes git2go.CredType) (*git2go.Cred, error) {
		cred, err := git2go.NewCredSshKeyFromMemory(user, "", string(identity), string(password))
		if err != nil {
			return nil, err
		}
		return cred, nil
	}
	certCallback := func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		// First, attempt to split the configured host and port to validate
		// the port-less hostname given to the callback.
		host, _, err := net.SplitHostPort(s.host)
		if err != nil {
			// SplitHostPort returns an error if the host is missing
			// a port, assume the host has no port.
			host = s.host
		}

		// Check if the configured host matches the hostname given to
		// the callback.
		if host != hostname {
			return git2go.ErrUser
		}

		// We are now certain that the configured host and the hostname
		// given to the callback match. Use the configured host (that
		// includes the port), and normalize it so we can check if there
		// is an entry for the hostname _and_ port.
		host = knownhosts.Normalize(s.host)
		for _, k := range kk {
			if k.matches(host, cert.Hostkey) {
				return git2go.ErrOk
			}
		}
		return git2go.ErrCertificate
	}

	return &git.Auth{CredCallback: credCallback, CertCallback: certCallback}, nil
}

type knownKey struct {
	hosts []string
	key   ssh.PublicKey
}

func parseKnownHosts(s string) ([]knownKey, error) {
	var knownHosts []knownKey
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

func (k knownKey) matches(host string, hostkey git2go.HostkeyCertificate) bool {
	if !containsHost(k.hosts, host) {
		return false
	}

	var fingerprint []byte
	var hasher hash.Hash
	switch {
	case hostkey.Kind&git2go.HostkeySHA256 > 0:
		fingerprint = hostkey.HashSHA256[:]
		hasher = sha256.New()
	case hostkey.Kind&git2go.HostkeySHA1 > 0:
		fingerprint = hostkey.HashSHA1[:]
		hasher = sha1.New()
	case hostkey.Kind&git2go.HostkeyMD5 > 0:
		fingerprint = hostkey.HashMD5[:]
		hasher = md5.New()
	default:
		return false
	}
	hasher.Write(k.key.Marshal())
	return bytes.Compare(hasher.Sum(nil), fingerprint) == 0
}

func containsHost(hosts []string, host string) bool {
	for _, h := range hosts {
		if h == host {
			return true
		}
	}

	return false
}
