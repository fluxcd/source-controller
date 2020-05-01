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
	"context"
	"fmt"

	"github.com/blang/semver"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

const (
	defaultOrigin = "origin"
	defaultBranch = "master"
)

func CheckoutStrategyForRef(ref *sourcev1.GitRepositoryRef) CheckoutStrategy {
	switch {
	case ref == nil:
		return &CheckoutBranch{branch: defaultBranch}
	case ref.SemVer != "":
		return &CheckoutSemVer{semVer: ref.SemVer}
	case ref.Tag != "":
		return &CheckoutTag{tag: ref.Tag}
	case ref.Commit != "":
		strategy := &CheckoutCommit{branch: ref.Branch, commit: ref.Commit}
		if strategy.branch == "" {
			strategy.branch = defaultBranch
		}
		return strategy
	case ref.Branch != "":
		return &CheckoutBranch{branch: ref.Branch}
	default:
		return &CheckoutBranch{branch: defaultBranch}
	}
}

type CheckoutStrategy interface {
	Checkout(ctx context.Context, path, url string, auth transport.AuthMethod) (*object.Commit, string, error)
}

type CheckoutBranch struct {
	branch string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, auth transport.AuthMethod) (*object.Commit, string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               url,
		Auth:              auth,
		RemoteName:        defaultOrigin,
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git clone error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Hash(), err)
	}
	return commit, fmt.Sprintf("%s/%s", c.branch, head.Hash().String()), nil
}

type CheckoutTag struct {
	tag string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, auth transport.AuthMethod) (*object.Commit, string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               url,
		Auth:              auth,
		RemoteName:        defaultOrigin,
		ReferenceName:     plumbing.NewTagReferenceName(c.tag),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git clone error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Hash(), err)
	}
	return commit, fmt.Sprintf("%s/%s", c.tag, head.Hash().String()), nil
}

type CheckoutCommit struct {
	branch string
	commit string
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path, url string, auth transport.AuthMethod) (*object.Commit, string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               url,
		Auth:              auth,
		RemoteName:        defaultOrigin,
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git clone error: %w", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		return nil, "", fmt.Errorf("git worktree error: %w", err)
	}
	commit, err := repo.CommitObject(plumbing.NewHash(c.commit))
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", c.commit, err)
	}
	err = w.Checkout(&git.CheckoutOptions{
		Hash:  commit.Hash,
		Force: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}
	return commit, fmt.Sprintf("%s/%s", c.branch, commit.Hash.String()), nil
}

type CheckoutSemVer struct {
	semVer string
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, auth transport.AuthMethod) (*object.Commit, string, error) {
	rng, err := semver.ParseRange(c.semVer)
	if err != nil {
		return nil, "", fmt.Errorf("semver parse range error: %w", err)
	}

	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               url,
		Auth:              auth,
		RemoteName:        defaultOrigin,
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.AllTags,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git clone error: %w", err)
	}

	repoTags, err := repo.Tags()
	if err != nil {
		return nil, "", fmt.Errorf("git list tags error: %w", err)
	}

	tags := make(map[string]string)
	_ = repoTags.ForEach(func(t *plumbing.Reference) error {
		tags[t.Name().Short()] = t.Strings()[1]
		return nil
	})

	svTags := make(map[string]string)
	var svers []semver.Version
	for tag, _ := range tags {
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
	commitRef := tags[t]

	w, err := repo.Worktree()
	if err != nil {
		return nil, "", fmt.Errorf("git worktree error: %w", err)
	}

	commit, err := repo.CommitObject(plumbing.NewHash(commitRef))
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", commitRef, err)
	}
	err = w.Checkout(&git.CheckoutOptions{
		Hash: commit.Hash,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}

	return commit, fmt.Sprintf("%s/%s", t, commitRef), nil
}
