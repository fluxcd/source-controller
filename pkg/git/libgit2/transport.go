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
	"hash"
	"net"
	"strings"
	"time"

	git2go "github.com/libgit2/git2go/v31"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/fluxcd/source-controller/pkg/git"
)

var (
	now = time.Now
)

// remoteCallbacks constructs RemoteCallbacks with credentialsCallback and
// certificateCallback, and the given options if the given opts is not nil.
func remoteCallbacks(opts *git.AuthOptions) git2go.RemoteCallbacks {
	if opts != nil {
		return git2go.RemoteCallbacks{
			CredentialsCallback:      credentialsCallback(opts),
			CertificateCheckCallback: certificateCallback(opts),
		}
	}
	return git2go.RemoteCallbacks{}
}

// credentialsCallback constructs CredentialsCallbacks with the given options
// for git.Transport if the given opts is not nil, and returns the result.
func credentialsCallback(opts *git.AuthOptions) git2go.CredentialsCallback {
	switch opts.Transport {
	case git.HTTP:
		if opts.Username != "" {
			return func(u string, user string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {
				return git2go.NewCredentialUsername(opts.Username)
			}
		}
	case git.HTTPS:
		if opts.Username != "" && opts.Password != "" {
			return func(u string, user string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {
				return git2go.NewCredentialUserpassPlaintext(opts.Username, opts.Password)
			}
		}
	case git.SSH:
		if len(opts.Identity) > 0 {
			return func(u string, user string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {
				return git2go.NewCredentialSSHKeyFromMemory(opts.Username, "", string(opts.Identity), opts.Password)
			}
		}
	}
	return nil
}

// certificateCallback constructs CertificateCallback with the given options
// for git.Transport if the given opts is not nil, and returns the result.
func certificateCallback(opts *git.AuthOptions) git2go.CertificateCheckCallback {
	switch opts.Transport {
	case git.HTTPS:
		if len(opts.CAFile) > 0 {
			return x509Callback(opts.CAFile)
		}
	case git.SSH:
		if len(opts.KnownHosts) > 0 && opts.Host != "" {
			return knownHostsCallback(opts.Host, opts.KnownHosts)
		}
	}
	return nil
}

// x509Callback returns a CertificateCheckCallback that verifies the
// certificate against the given caBundle for git.HTTPS Transports.
func x509Callback(caBundle []byte) git2go.CertificateCheckCallback {
	return func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(caBundle); !ok {
			return git2go.ErrorCodeCertificate
		}

		opts := x509.VerifyOptions{
			Roots:       roots,
			DNSName:     hostname,
			CurrentTime: now(),
		}
		if _, err := cert.X509.Verify(opts); err != nil {
			return git2go.ErrorCodeCertificate
		}
		return git2go.ErrorCodeOK
	}
}

// knownHostCallback returns a CertificateCheckCallback that verifies
// the key of Git server against the given host and known_hosts for
// git.SSH Transports.
func knownHostsCallback(host string, knownHosts []byte) git2go.CertificateCheckCallback {
	return func(cert *git2go.Certificate, valid bool, hostname string) git2go.ErrorCode {
		kh, err := parseKnownHosts(string(knownHosts))
		if err != nil {
			return git2go.ErrorCodeCertificate
		}

		// First, attempt to split the configured host and port to validate
		// the port-less hostname given to the callback.
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			// SplitHostPort returns an error if the host is missing
			// a port, assume the host has no port.
			h = host
		}

		// Check if the configured host matches the hostname given to
		// the callback.
		if h != hostname {
			return git2go.ErrorCodeUser
		}

		// We are now certain that the configured host and the hostname
		// given to the callback match. Use the configured host (that
		// includes the port), and normalize it, so we can check if there
		// is an entry for the hostname _and_ port.
		h = knownhosts.Normalize(host)
		for _, k := range kh {
			if k.matches(h, cert.Hostkey) {
				return git2go.ErrorCodeOK
			}
		}
		return git2go.ErrorCodeCertificate
	}
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
