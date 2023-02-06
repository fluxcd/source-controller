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

package util

import (
	"github.com/fluxcd/go-git/v5/plumbing/transport"
	"github.com/fluxcd/go-git/v5/plumbing/transport/http"
	gogit "github.com/fluxcd/go-git/v5/plumbing/transport/ssh"
	git "github.com/fluxcd/pkg/git"
	"golang.org/x/crypto/ssh"
)

func AuthGit(authOpts *git.AuthOptions) (transport.AuthMethod, []byte, error) {

	if authOpts.Transport == git.HTTPS {
		if authOpts.BearerToken != "" {
			return &http.TokenAuth{
				Token: authOpts.BearerToken,
			}, authOpts.CAFile, nil
		}
		return &http.BasicAuth{
			Username: authOpts.Username,
			Password: authOpts.Password,
		}, authOpts.CAFile, nil
	}

	if authOpts.Transport == git.SSH {
		if authOpts.Identity != nil {
			var signer ssh.Signer
			if authOpts.Password != "" {
				var err error
				signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(authOpts.Identity), []byte(authOpts.Password))
				if err != nil {
					return nil, nil, err
				}
			}
			//ToDo(haarchri): ssh: must specify HostKeyCallback"
			return &gogit.PublicKeys{
				User:   "git",
				Signer: signer,
			}, authOpts.CAFile, nil
		}
	}

	return nil, nil, nil
}
