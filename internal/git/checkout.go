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
)

type CheckoutStrategy interface {
	Checkout(ctx context.Context, path string) error
}

type CheckoutBranch struct {
	url    string
	branch string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path string) (string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               c.url,
		RemoteName:        "origin",
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("git clone error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf(" git resolve HEAD error: %w", err)
	}
	return fmt.Sprintf("%s/%s", c.branch, head.Hash().String()), nil
}

type CheckoutTag struct {
	url string
	tag string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path string) (string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               c.url,
		RemoteName:        "origin",
		ReferenceName:     plumbing.NewTagReferenceName(c.tag),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("git clone error: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf(" git resolve HEAD error: %w", err)
	}
	return fmt.Sprintf("%s/%s", c.tag, head.Hash().String()), nil
}

type CheckoutCommit struct {
	url    string
	branch string
	commit string
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path string) (string, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               c.url,
		RemoteName:        "origin",
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("git clone error: %w", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("git worktree error: %w", err)
	}
	commit, err := repo.CommitObject(plumbing.NewHash(c.commit))
	if err != nil {
		return "", fmt.Errorf("git commit not found: %w", err)
	}
	err = w.Checkout(&git.CheckoutOptions{
		Hash:  commit.Hash,
		Force: true,
	})
	if err != nil {
		return "", fmt.Errorf("git checkout error: %w", err)
	}
	return fmt.Sprintf("%s/%s", c.branch, commit.Hash.String()), nil
}

type CheckoutSemVer struct {
	url    string
	semver string
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path string) (string, error) {
	rng, err := semver.ParseRange(c.semver)
	if err != nil {
		return "", fmt.Errorf("semver parse range error: %w", err)
	}

	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:               c.url,
		RemoteName:        "origin",
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              git.AllTags,
	})
	if err != nil {
		return "", fmt.Errorf("git clone error: %w", err)
	}

	repoTags, err := repo.Tags()
	if err != nil {
		return "", fmt.Errorf("git list tags error: %w", err)
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
		return "", fmt.Errorf("no match found for semver: %s", c.semver)
	}

	semver.Sort(svers)
	v := svers[len(svers)-1]
	t := svTags[v.String()]
	commit := tags[t]

	w, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("git worktree error: %w", err)
	}

	err = w.Checkout(&git.CheckoutOptions{
		Hash: plumbing.NewHash(commit),
	})
	if err != nil {
		return "", fmt.Errorf("git checkout error: %w", err)
	}

	return fmt.Sprintf("%s/%s", t, commit), nil
}
