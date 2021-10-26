/*
Copyright 2021 The Flux authors

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
	"net/url"

	v1 "k8s.io/api/core/v1"
)

const (
	DefaultOrigin            = "origin"
	DefaultBranch            = "master"
	DefaultPublicKeyAuthUser = "git"
)

// CheckoutOptions are the options used for a Git checkout.
type CheckoutOptions struct {
	// Branch to checkout, can be combined with Branch with some
	// Implementations.
	Branch string

	// Tag to checkout, takes precedence over Branch.
	Tag string

	// SemVer tag expression to checkout, takes precedence over Tag.
	SemVer string `json:"semver,omitempty"`

	// Commit SHA1 to checkout, takes precedence over Tag and SemVer,
	// can be combined with Branch with some Implementations.
	Commit string

	// RecurseSubmodules defines if submodules should be checked out,
	// not supported by all Implementations.
	RecurseSubmodules bool
}

type TransportType string

const (
	SSH   TransportType = "ssh"
	HTTPS TransportType = "https"
	HTTP  TransportType = "http"
)

// AuthOptions are the authentication options for the Transport of
// communication with a remote origin.
type AuthOptions struct {
	Transport  TransportType
	Host       string
	Username   string
	Password   string
	Identity   []byte
	KnownHosts []byte
	CAFile     []byte
}

// Validate the AuthOptions against the defined Transport.
func (o AuthOptions) Validate() error {
	switch o.Transport {
	case HTTPS, HTTP:
		if o.Username == "" && o.Password != "" {
			return fmt.Errorf("invalid '%s' auth option: 'password' requires 'username' to be set", o.Transport)
		}
	case SSH:
		if o.Host == "" {
			return fmt.Errorf("invalid '%s' auth option: 'host' is required", o.Transport)
		}
		if len(o.Identity) == 0 {
			return fmt.Errorf("invalid '%s' auth option: 'identity' is required", o.Transport)
		}
		if len(o.KnownHosts) == 0 {
			return fmt.Errorf("invalid '%s' auth option: 'known_hosts' is required", o.Transport)
		}
	case "":
		return fmt.Errorf("no transport type set")
	default:
		return fmt.Errorf("unknown transport '%s'", o.Transport)
	}
	return nil
}

// AuthOptionsFromSecret constructs an AuthOptions object from the given Secret,
// and then validates the result. It returns the AuthOptions, or an error.
func AuthOptionsFromSecret(URL string, secret *v1.Secret) (*AuthOptions, error) {
	if secret == nil {
		return nil, fmt.Errorf("no secret provided to construct auth strategy from")
	}

	u, err := url.Parse(URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL to determine auth strategy: %w", err)
	}

	opts := &AuthOptions{
		Transport:  TransportType(u.Scheme),
		Host:       u.Host,
		Username:   string(secret.Data["username"]),
		Password:   string(secret.Data["password"]),
		CAFile:     secret.Data["caFile"],
		Identity:   secret.Data["identity"],
		KnownHosts: secret.Data["known_hosts"],
	}
	if opts.Username == "" {
		opts.Username = u.User.Username()
	}
	if opts.Username == "" {
		opts.Username = DefaultPublicKeyAuthUser
	}

	if err = opts.Validate(); err != nil {
		return nil, err
	}

	return opts, nil
}
