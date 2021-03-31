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
	"fmt"

	"github.com/blang/semver/v4"
	git2go "github.com/libgit2/git2go/v31"

	"github.com/fluxcd/pkg/gitutil"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git"
)

func CheckoutStrategyForRef(ref *sourcev1.GitRepositoryRef, opt git.CheckoutOptions) git.CheckoutStrategy {
	switch {
	case ref == nil:
		return &CheckoutBranch{branch: git.DefaultBranch}
	case ref.SemVer != "":
		return &CheckoutSemVer{semVer: ref.SemVer}
	case ref.Tag != "":
		return &CheckoutTag{tag: ref.Tag}
	case ref.Commit != "":
		strategy := &CheckoutCommit{branch: ref.Branch, commit: ref.Commit}
		if strategy.branch == "" {
			strategy.branch = git.DefaultBranch
		}
		return strategy
	case ref.Branch != "":
		return &CheckoutBranch{branch: ref.Branch}
	default:
		return &CheckoutBranch{branch: git.DefaultBranch}
	}
}

type CheckoutBranch struct {
	branch string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags: git2go.DownloadTagsNone,
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback:      auth.CredCallback,
				CertificateCheckCallback: auth.CertCallback,
			},
		},
		CheckoutBranch: c.branch,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, gitutil.LibGit2Error(err))
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Target(), err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.branch, head.Target().String()), nil
}

type CheckoutTag struct {
	tag string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags: git2go.DownloadTagsAll,
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback:      auth.CredCallback,
				CertificateCheckCallback: auth.CertCallback,
			},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}
	ref, err := repo.References.Dwim(c.tag)
	if err != nil {
		return nil, "", fmt.Errorf("unable to find tag '%s': %w", c.tag, err)
	}
	err = repo.SetHeadDetached(ref.Target())
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Target(), err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.tag, head.Target().String()), nil
}

type CheckoutCommit struct {
	branch string
	commit string
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags: git2go.DownloadTagsNone,
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback:      auth.CredCallback,
				CertificateCheckCallback: auth.CertCallback,
			},
		},
		CheckoutBranch: c.branch,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}
	oid, err := git2go.NewOid(c.commit)
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' could not be parsed", c.commit)
	}
	commit, err := repo.LookupCommit(oid)
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", c.commit, err)
	}
	tree, err := repo.LookupTree(commit.TreeId())
	if err != nil {
		return nil, "", fmt.Errorf("git worktree error: %w", err)
	}
	err = repo.CheckoutTree(tree, &git2go.CheckoutOpts{
		Strategy: git2go.CheckoutForce,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}

	return &Commit{commit}, fmt.Sprintf("%s/%s", c.branch, commit.Id().String()), nil
}

type CheckoutSemVer struct {
	semVer string
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	rng, err := semver.ParseRange(c.semVer)
	if err != nil {
		return nil, "", fmt.Errorf("semver parse range error: %w", err)
	}

	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags: git2go.DownloadTagsAll,
			RemoteCallbacks: git2go.RemoteCallbacks{
				CredentialsCallback:      auth.CredCallback,
				CertificateCheckCallback: auth.CertCallback,
			},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}

	repoTags, err := repo.Tags.List()
	if err != nil {
		return nil, "", fmt.Errorf("git list tags error: %w", err)
	}

	svTags := make(map[string]string)
	var svers []semver.Version
	for _, tag := range repoTags {
		v, _ := semver.ParseTolerant(tag)
		if rng(v) {
			svers = append(svers, v)
			svTags[v.String()] = tag
		}
	}

	if len(svers) == 0 {
		return nil, "", fmt.Errorf("no match found for semver: %s", c.semVer)
	}

	semver.Sort(svers)
	v := svers[len(svers)-1]
	t := svTags[v.String()]

	ref, err := repo.References.Dwim(t)
	if err != nil {
		return nil, "", fmt.Errorf("unable to find tag '%s': %w", t, err)
	}
	err = repo.SetHeadDetached(ref.Target())
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Target().String(), err)
	}

	return &Commit{commit}, fmt.Sprintf("%s/%s", t, head.Target().String()), nil
}
