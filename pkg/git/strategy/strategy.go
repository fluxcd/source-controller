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

package strategy

import (
	"fmt"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
)

func CheckoutStrategyForRef(ref *sourcev1.GitRepositoryRef, gitImplementation string) (git.CheckoutStrategy, error) {
	switch gitImplementation {
	case sourcev1.GoGitImplementation:
		return gogit.CheckoutStrategyForRef(ref), nil
	case sourcev1.LibGit2Implementation:
		return libgit2.CheckoutStrategyForRef(ref), nil
	default:
		return nil, fmt.Errorf("invalid git implementation %s", gitImplementation)
	}
}

func AuthSecretStrategyForURL(url string, gitImplementation string) (git.AuthSecretStrategy, error) {
	switch gitImplementation {
	case sourcev1.GoGitImplementation:
		return gogit.AuthSecretStrategyForURL(url)
	case sourcev1.LibGit2Implementation:
		return libgit2.AuthSecretStrategyForURL(url)
	default:
		return nil, fmt.Errorf("invalid git implementation %s", gitImplementation)
	}
}
