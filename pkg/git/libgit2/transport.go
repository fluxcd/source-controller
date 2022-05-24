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
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"time"

	git2go "github.com/libgit2/git2go/v33"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/fluxcd/source-controller/pkg/git"
)

var (
	now = time.Now
)

// RemoteCallbacks constructs RemoteCallbacks with credentialsCallback and
// certificateCallback, and the given options if the given opts is not nil.
func RemoteCallbacks(ctx context.Context, opts *git.AuthOptions) git2go.RemoteCallbacks {
	if opts != nil {
		return git2go.RemoteCallbacks{
			SidebandProgressCallback:     transportMessageCallback(ctx),
			TransferProgressCallback:     transferProgressCallback(ctx),
			PushTransferProgressCallback: pushTransferProgressCallback(ctx),
			CredentialsCallback:          credentialsCallback(opts),
			CertificateCheckCallback:     certificateCallback(opts),
		}
	}
	return git2go.RemoteCallbacks{}
}

// transferProgressCallback constructs TransferProgressCallbacks which signals
// libgit2 it should stop the transfer when the given context is closed (due to
// e.g. a timeout).
func transferProgressCallback(ctx context.Context) git2go.TransferProgressCallback {
	return func(p git2go.TransferProgress) error {
		// Early return if all the objects have been received.
		if p.ReceivedObjects == p.TotalObjects {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("transport close (potentially due to a timeout)")
		default:
			return nil
		}
	}
}

// transportMessageCallback constructs TransportMessageCallback which signals
// libgit2 it should cancel the network operation when the given context is
// closed.
func transportMessageCallback(ctx context.Context) git2go.TransportMessageCallback {
	return func(_ string) error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("transport closed")
		default:
			return nil
		}
	}
}

// pushTransferProgressCallback constructs PushTransferProgressCallback which
// signals libgit2 it should stop the push transfer when the given context is
// closed (due to e.g. a timeout).
func pushTransferProgressCallback(ctx context.Context) git2go.PushTransferProgressCallback {
	return func(current, total uint32, _ uint) error {
		// Early return if current equals total.
		if current == total {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("transport close (potentially due to a timeout)")
		default:
			return nil
		}
	}
}

// credentialsCallback constructs CredentialsCallbacks with the given options
// for git.Transport, and returns the result.
func credentialsCallback(opts *git.AuthOptions) git2go.CredentialsCallback {
	return func(url string, username string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {
		if allowedTypes&(git2go.CredentialTypeSSHKey|git2go.CredentialTypeSSHCustom|git2go.CredentialTypeSSHMemory) != 0 {
			var (
				signer ssh.Signer
				err    error
			)
			if opts.Password != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(opts.Identity, []byte(opts.Password))
			} else {
				signer, err = ssh.ParsePrivateKey(opts.Identity)
			}
			if err != nil {
				return nil, err
			}
			return git2go.NewCredentialSSHKeyFromSigner(opts.Username, signer)
		}
		if (allowedTypes & git2go.CredentialTypeUserpassPlaintext) != 0 {
			return git2go.NewCredentialUserpassPlaintext(opts.Username, opts.Password)
		}
		if (allowedTypes & git2go.CredentialTypeUsername) != 0 {
			return git2go.NewCredentialUsername(opts.Username)
		}
		return nil, fmt.Errorf("unknown credential type %+v", allowedTypes)
	}
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
	return func(cert *git2go.Certificate, valid bool, hostname string) error {
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(caBundle); !ok {
			return fmt.Errorf("PEM CA bundle could not be appended to x509 certificate pool")
		}

		opts := x509.VerifyOptions{
			Roots:       roots,
			DNSName:     hostname,
			CurrentTime: now(),
		}
		if _, err := cert.X509.Verify(opts); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		return nil
	}
}

// knownHostCallback returns a CertificateCheckCallback that verifies
// the key of Git server against the given host and known_hosts for
// git.SSH Transports.
func knownHostsCallback(host string, knownHosts []byte) git2go.CertificateCheckCallback {
	return func(cert *git2go.Certificate, valid bool, hostname string) error {
		kh, err := parseKnownHosts(string(knownHosts))
		if err != nil {
			return fmt.Errorf("failed to parse known_hosts: %w", err)
		}

		// First, attempt to split the configured host and port to validate
		// the port-less hostname given to the callback.
		hostWithoutPort, _, err := net.SplitHostPort(host)
		if err != nil {
			// SplitHostPort returns an error if the host is missing
			// a port, assume the host has no port.
			hostWithoutPort = host
		}

		// Different versions of libgit handle this differently.
		// This fixes the case in which ports may be sent back.
		hostnameWithoutPort, _, err := net.SplitHostPort(hostname)
		if err != nil {
			hostnameWithoutPort = hostname
		}

		if hostnameWithoutPort != hostWithoutPort {
			return fmt.Errorf("host mismatch: %q %q", hostWithoutPort, hostnameWithoutPort)
		}

		// We are now certain that the configured host and the hostname
		// given to the callback match. Use the configured host (that
		// includes the port), and normalize it, so we can check if there
		// is an entry for the hostname _and_ port.
		h := knownhosts.Normalize(host)
		for _, k := range kh {
			if k.matches(h, cert.Hostkey) {
				return nil
			}
		}
		return fmt.Errorf("hostkey could not be verified")
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
			// Lines that aren't host public key result in EOF, like a comment
			// line. Continue parsing the other lines.
			if err == io.EOF {
				continue
			}
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
	return bytes.Equal(hasher.Sum(nil), fingerprint)
}

func containsHost(hosts []string, host string) bool {
	for _, kh := range hosts {
		// hashed host must start with a pipe
		if kh[0] == '|' {
			match, _ := MatchHashedHost(kh, host)
			if match {
				return true
			}

		} else if kh == host { // unhashed host check
			return true
		}
	}
	return false
}

// MatchHashedHost tries to match a hashed known host (kh) to
// host.
//
// Note that host is not hashed, but it is rather hashed during
// the matching process using the same salt used when hashing
// the known host.
func MatchHashedHost(kh, host string) (bool, error) {
	if kh == "" || kh[0] != '|' {
		return false, fmt.Errorf("hashed known host must begin with '|': '%s'", kh)
	}

	components := strings.Split(kh, "|")
	if len(components) != 4 {
		return false, fmt.Errorf("invalid format for hashed known host: '%s'", kh)
	}

	if components[1] != "1" {
		return false, fmt.Errorf("unsupported hash type '%s'", components[1])
	}

	hkSalt, err := base64.StdEncoding.DecodeString(components[2])
	if err != nil {
		return false, fmt.Errorf("cannot decode hashed known host: '%w'", err)
	}

	hkHash, err := base64.StdEncoding.DecodeString(components[3])
	if err != nil {
		return false, fmt.Errorf("cannot decode hashed known host: '%w'", err)
	}

	mac := hmac.New(sha1.New, hkSalt)
	mac.Write([]byte(host))
	hostHash := mac.Sum(nil)

	return bytes.Equal(hostHash, hkHash), nil
}
