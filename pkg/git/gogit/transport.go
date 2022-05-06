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

package gogit

import (
	"fmt"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"

	"github.com/fluxcd/pkg/ssh/knownhosts"

	"github.com/fluxcd/source-controller/pkg/git"

	gossh "golang.org/x/crypto/ssh"
)

// transportAuth constructs the transport.AuthMethod for the git.Transport of
// the given git.AuthOptions. It returns the result, or an error.
func transportAuth(opts *git.AuthOptions) (transport.AuthMethod, error) {
	if opts == nil {
		return nil, nil
	}
	switch opts.Transport {
	case git.HTTPS, git.HTTP:
		// Some providers (i.e. GitLab) will reject empty credentials for
		// public repositories.
		if opts.Username != "" || opts.Password != "" {
			return &http.BasicAuth{
				Username: opts.Username,
				Password: opts.Password,
			}, nil
		}
		return nil, nil
	case git.SSH:
		if len(opts.Identity) > 0 {
			pk, err := ssh.NewPublicKeys(opts.Username, opts.Identity, opts.Password)
			if err != nil {
				return nil, err
			}
			if len(opts.KnownHosts) > 0 {
				callback, err := knownhosts.New(opts.KnownHosts)
				if err != nil {
					return nil, err
				}
				pk.HostKeyCallback = callback
			}
			customPK := &CustomPublicKeys{
				pk: pk,
			}
			return customPK, nil
		}
	case "":
		return nil, fmt.Errorf("no transport type set")
	default:
		return nil, fmt.Errorf("unknown transport '%s'", opts.Transport)
	}
	return nil, nil
}

// caBundle returns the CA bundle from the given git.AuthOptions.
func caBundle(opts *git.AuthOptions) []byte {
	if opts == nil {
		return nil
	}
	return opts.CAFile
}

// CustomPublicKeys is a wrapper around ssh.PublicKeys to help us
// customize the ssh config. It implements ssh.AuthMethod.
type CustomPublicKeys struct {
	pk *ssh.PublicKeys
}

func (a *CustomPublicKeys) Name() string {
	return a.pk.Name()
}

func (a *CustomPublicKeys) String() string {
	return a.pk.String()
}

func (a *CustomPublicKeys) ClientConfig() (*gossh.ClientConfig, error) {
	config, err := a.pk.ClientConfig()
	if err != nil {
		return nil, err
	}
	if len(git.KexAlgos) > 0 {
		config.Config.KeyExchanges = git.KexAlgos
	}
	if len(git.HostKeyAlgos) > 0 {
		config.HostKeyAlgorithms = git.HostKeyAlgos
	}

	return config, nil
}
