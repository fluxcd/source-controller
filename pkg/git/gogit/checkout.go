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
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"
	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/fluxcd/pkg/gitutil"
	"github.com/fluxcd/pkg/version"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git"
)

func CheckoutStrategyForRef(ref *sourcev1.GitRepositoryRef, opt git.CheckoutOptions) git.CheckoutStrategy {
	switch {
	case ref == nil:
		return &CheckoutBranch{branch: git.DefaultBranch}
	case ref.SemVer != "":
		return &CheckoutSemVer{semVer: ref.SemVer, recurseSubmodules: opt.RecurseSubmodules}
	case ref.Tag != "":
		return &CheckoutTag{tag: ref.Tag, recurseSubmodules: opt.RecurseSubmodules}
	case ref.Commit != "":
		strategy := &CheckoutCommit{branch: ref.Branch, commit: ref.Commit, recurseSubmodules: opt.RecurseSubmodules}
		if strategy.branch == "" {
			strategy.branch = git.DefaultBranch
		}
		return strategy
	case ref.Branch != "":
		return &CheckoutBranch{branch: ref.Branch, recurseSubmodules: opt.RecurseSubmodules}
	default:
		return &CheckoutBranch{branch: git.DefaultBranch}
	}
}

type CheckoutBranch struct {
	branch            string
	recurseSubmodules bool
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              auth.AuthMethod,
		RemoteName:        git.DefaultOrigin,
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.recurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          auth.CABundle,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, gitutil.GoGitError(err))
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Hash(), err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.branch, head.Hash().String()), nil
}

type CheckoutTag struct {
	tag               string
	recurseSubmodules bool
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              auth.AuthMethod,
		RemoteName:        git.DefaultOrigin,
		ReferenceName:     plumbing.NewTagReferenceName(c.tag),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.recurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          auth.CABundle,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Hash(), err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.tag, head.Hash().String()), nil
}

type CheckoutCommit struct {
	branch            string
	commit            string
	recurseSubmodules bool
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              auth.AuthMethod,
		RemoteName:        git.DefaultOrigin,
		ReferenceName:     plumbing.NewBranchReferenceName(c.branch),
		SingleBranch:      true,
		NoCheckout:        false,
		RecurseSubmodules: recurseSubmodules(c.recurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          auth.CABundle,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}
	w, err := repo.Worktree()
	if err != nil {
		return nil, "", fmt.Errorf("git worktree error: %w", err)
	}
	commit, err := repo.CommitObject(plumbing.NewHash(c.commit))
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", c.commit, err)
	}
	err = w.Checkout(&extgogit.CheckoutOptions{
		Hash:  commit.Hash,
		Force: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.branch, commit.Hash.String()), nil
}

type CheckoutSemVer struct {
	semVer            string
	recurseSubmodules bool
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	verConstraint, err := semver.NewConstraint(c.semVer)
	if err != nil {
		return nil, "", fmt.Errorf("semver parse range error: %w", err)
	}

	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              auth.AuthMethod,
		RemoteName:        git.DefaultOrigin,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.recurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.AllTags,
		CABundle:          auth.CABundle,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, err)
	}

	repoTags, err := repo.Tags()
	if err != nil {
		return nil, "", fmt.Errorf("git list tags error: %w", err)
	}

	tags := make(map[string]string)
	tagTimestamps := make(map[string]time.Time)
	_ = repoTags.ForEach(func(t *plumbing.Reference) error {
		revision := plumbing.Revision(t.Name().String())
		hash, err := repo.ResolveRevision(revision)
		if err != nil {
			return fmt.Errorf("unable to resolve tag revision: %w", err)
		}
		commit, err := repo.CommitObject(*hash)
		if err != nil {
			return fmt.Errorf("unable to resolve commit of a tag revision: %w", err)
		}
		tagTimestamps[t.Name().Short()] = commit.Committer.When

		tags[t.Name().Short()] = t.Strings()[1]
		return nil
	})

	var matchedVersions semver.Collection
	for tag, _ := range tags {
		v, err := version.ParseVersion(tag)
		if err != nil {
			continue
		}
		if !verConstraint.Check(v) {
			continue
		}
		matchedVersions = append(matchedVersions, v)
	}
	if len(matchedVersions) == 0 {
		return nil, "", fmt.Errorf("no match found for semver: %s", c.semVer)
	}

	// Sort versions
	sort.SliceStable(matchedVersions, func(i, j int) bool {
		left := matchedVersions[i]
		right := matchedVersions[j]

		if !left.Equal(right) {
			return left.LessThan(right)
		}

		// Having tag target timestamps at our disposal, we further try to sort
		// versions into a chronological order. This is especially important for
		// versions that differ only by build metadata, because it is not considered
		// a part of the comparable version in Semver
		return tagTimestamps[left.String()].Before(tagTimestamps[right.String()])
	})
	v := matchedVersions[len(matchedVersions)-1]
	t := v.Original()

	w, err := repo.Worktree()
	if err != nil {
		return nil, "", fmt.Errorf("git worktree error: %w", err)
	}

	err = w.Checkout(&extgogit.CheckoutOptions{
		Branch: plumbing.NewTagReferenceName(t),
	})
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("git resolve HEAD error: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", fmt.Errorf("git commit '%s' not found: %w", head.Hash(), err)
	}

	return &Commit{commit}, fmt.Sprintf("%s/%s", t, head.Hash().String()), nil
}

func recurseSubmodules(recurse bool) extgogit.SubmoduleRescursivity {
	if recurse {
		return extgogit.DefaultSubmoduleRecursionDepth
	}
	return extgogit.NoRecurseSubmodules
}
