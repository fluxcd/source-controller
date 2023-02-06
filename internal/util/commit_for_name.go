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
	"errors"

	"github.com/fluxcd/go-git/v5"
	"github.com/fluxcd/go-git/v5/config"
	"github.com/fluxcd/go-git/v5/storage/memory"
)

type GitName struct {
	rem git.Remote
}

func (g *GitName) GetGitCommitForName(name string, o *git.ListOptions) (string, error) {
	refs, err := g.rem.List(o)
	if err != nil {
		return "", err
	}

	branchCommit := ""
	for _, ref := range refs {
		if ref.Name().Short() == name {
			if ref.Name().IsTag() {
				return ref.Hash().String(), nil
			} else if ref.Name().IsBranch() {
				branchCommit = ref.Hash().String()
			}
		}
	}

	if branchCommit != "" {
		return branchCommit, nil
	}

	return "", errors.New("no commit found for name:" + name)
}

func NewGitName(config *config.RemoteConfig) (GitName, error) {
	return GitName{rem: *git.NewRemote(memory.NewStorage(), config)}, nil
}
