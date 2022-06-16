package managed

import (
	"encoding/base64"
	"fmt"
	"net"

	pkgkh "github.com/fluxcd/pkg/ssh/knownhosts"
	git2go "github.com/libgit2/git2go/v33"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostCallback returns a CertificateCheckCallback that verifies
// the key of Git server against the given host and known_hosts for
// git.SSH Transports.
func KnownHostsCallback(host string, knownHosts []byte) git2go.CertificateCheckCallback {
	return func(cert *git2go.Certificate, valid bool, hostname string) error {
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

		var fingerprint []byte
		switch {
		case cert.Hostkey.Kind&git2go.HostkeySHA256 > 0:
			fingerprint = cert.Hostkey.HashSHA256[:]
		default:
			return fmt.Errorf("invalid host key kind, expected to be of kind SHA256")
		}

		return CheckKnownHost(host, knownHosts, fingerprint)
	}
}

// CheckKnownHost checks whether the host being connected to is
// part of the known_hosts, and if so, it ensures the host
// fingerprint matches the fingerprint of the known host with
// the same name.
func CheckKnownHost(host string, knownHosts []byte, fingerprint []byte) error {
	kh, err := pkgkh.ParseKnownHosts(string(knownHosts))
	if err != nil {
		return fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	if len(kh) == 0 {
		return fmt.Errorf("hostkey verification aborted: no known_hosts found")
	}

	// We are now certain that the configured host and the hostname
	// given to the callback match. Use the configured host (that
	// includes the port), and normalize it, so we can check if there
	// is an entry for the hostname _and_ port.
	h := knownhosts.Normalize(host)
	for _, k := range kh {
		if k.Matches(h, fingerprint) {
			return nil
		}
	}
	return fmt.Errorf("no entries in known_hosts match host '%s' with fingerprint '%s'",
		h, base64.RawStdEncoding.EncodeToString(fingerprint))
}

// RemoteCallbacks constructs git2go.RemoteCallbacks with dummy callbacks.
func RemoteCallbacks() git2go.RemoteCallbacks {
	// This may not be fully removed as without some of the callbacks git2go
	// gets anxious and panics.
	return git2go.RemoteCallbacks{
		CredentialsCallback:      credentialsCallback(),
		CertificateCheckCallback: certificateCallback(),
	}
}

// credentialsCallback constructs a dummy CredentialsCallback.
func credentialsCallback() git2go.CredentialsCallback {
	return func(url string, username string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {
		// If credential is nil, panic will ensue. We fake it as managed transport does not
		// require it.
		return git2go.NewCredentialUserpassPlaintext("", "")
	}
}

// certificateCallback constructs a dummy CertificateCallback.
func certificateCallback() git2go.CertificateCheckCallback {
	// returning a nil func can cause git2go to panic.
	return func(cert *git2go.Certificate, valid bool, hostname string) error {
		return nil
	}
}
