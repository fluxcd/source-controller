/*
Copyright 2020 The Flux CD contributors.

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
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git/common"
	gitv1 "github.com/fluxcd/source-controller/pkg/git/v1"
	gitv2 "github.com/fluxcd/source-controller/pkg/git/v2"
)

const (
	defaultBranch = "master"
)

func CheckoutStrategyForRef(ref *sourcev1.GitRepositoryRef, useGitV2 bool) common.CheckoutStrategy {
	if useGitV2 {
		return gitv2.CheckoutStrategyForRef(ref)
	}

	return gitv1.CheckoutStrategyForRef(ref)
}

func AuthSecretStrategyForURL(url string, useGitV2 bool) (common.AuthSecretStrategy, error) {
	if useGitV2 {
		return gitv2.AuthSecretStrategyForURL(url)
	}

	return gitv1.AuthSecretStrategyForURL(url)
}
