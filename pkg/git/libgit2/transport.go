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
	"context"
	"crypto/x509"
	"fmt"
	"time"

	git2go "github.com/libgit2/git2go/v33"
	"golang.org/x/crypto/ssh"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
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
			return managed.KnownHostsCallback(opts.Host, opts.KnownHosts)
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
