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
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	git2go "github.com/libgit2/git2go/v31"

	"github.com/fluxcd/pkg/gitutil"
	"github.com/fluxcd/pkg/version"

	"github.com/fluxcd/source-controller/pkg/git"
)

// CheckoutStrategyForOptions returns the git.CheckoutStrategy for the given
// git.CheckoutOptions.
func CheckoutStrategyForOptions(ctx context.Context, opt git.CheckoutOptions) git.CheckoutStrategy {
	if opt.RecurseSubmodules {
		logr.FromContextOrDiscard(ctx).Info("git submodule recursion not supported by '%s'", Implementation)
	}
	switch {
	case opt.Commit != "":
		return &CheckoutCommit{Commit: opt.Commit}
	case opt.SemVer != "":
		return &CheckoutSemVer{SemVer: opt.SemVer}
	case opt.Tag != "":
		return &CheckoutTag{Tag: opt.Tag}
	default:
		branch := opt.Branch
		if branch == "" {
			branch = git.DefaultBranch
		}
		return &CheckoutBranch{Branch: branch}
	}
}

type CheckoutBranch struct {
	Branch string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsNone,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
		CheckoutBranch: c.Branch,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone: %w", gitutil.LibGit2Error(err))
	}
	defer repo.Free()
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("git resolve HEAD error: %w", err)
	}
	defer head.Free()
	cc, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, fmt.Errorf("could not find commit '%s' in branch '%s': %w", head.Target(), c.Branch, err)
	}
	defer cc.Free()
	return buildCommit(cc, "refs/heads/"+c.Branch), nil
}

type CheckoutTag struct {
	Tag string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsAll,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.LibGit2Error(err))
	}
	defer repo.Free()
	cc, err := checkoutDetachedDwim(repo, c.Tag)
	if err != nil {
		return nil, err
	}
	defer cc.Free()
	return buildCommit(cc, "refs/tags/"+c.Tag), nil
}

type CheckoutCommit struct {
	Commit string
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsNone,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.LibGit2Error(err))
	}
	defer repo.Free()
	oid, err := git2go.NewOid(c.Commit)
	if err != nil {
		return nil, fmt.Errorf("could not create oid for '%s': %w", c.Commit, err)
	}
	cc, err := checkoutDetachedHEAD(repo, oid)
	if err != nil {
		return nil, fmt.Errorf("git checkout error: %w", err)
	}
	return buildCommit(cc, ""), nil
}

type CheckoutSemVer struct {
	SemVer string
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	verConstraint, err := semver.NewConstraint(c.SemVer)
	if err != nil {
		return nil, fmt.Errorf("semver parse error: %w", err)
	}

	repo, err := git2go.Clone(url, path, &git2go.CloneOptions{
		FetchOptions: &git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsAll,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.LibGit2Error(err))
	}
	defer repo.Free()

	tags := make(map[string]string)
	tagTimestamps := make(map[string]time.Time)
	if err := repo.Tags.Foreach(func(name string, id *git2go.Oid) error {
		cleanName := strings.TrimPrefix(name, "refs/tags/")
		// The given ID can refer to both a commit and a tag, as annotated tags contain additional metadata.
		// Due to this, first attempt to resolve it as a simple tag (commit), but fallback to attempting to
		// resolve it as an annotated tag in case this results in an error.
		if c, err := repo.LookupCommit(id); err == nil {
			defer c.Free()
			// Use the commit metadata as the decisive timestamp.
			tagTimestamps[cleanName] = c.Committer().When
			tags[cleanName] = name
			return nil
		}
		t, err := repo.LookupTag(id)
		if err != nil {
			return fmt.Errorf("could not lookup '%s' as simple or annotated tag: %w", cleanName, err)
		}
		defer t.Free()
		commit, err := t.Peel(git2go.ObjectCommit)
		if err != nil {
			return fmt.Errorf("could not get commit for tag '%s': %w", t.Name(), err)
		}
		defer commit.Free()
		c, err := commit.AsCommit()
		if err != nil {
			return fmt.Errorf("could not get commit object for tag '%s': %w", t.Name(), err)
		}
		defer c.Free()
		tagTimestamps[t.Name()] = c.Committer().When
		tags[t.Name()] = name
		return nil
	}); err != nil {
		return nil, err
	}

	var matchedVersions semver.Collection
	for tag := range tags {
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
		return nil, fmt.Errorf("no match found for semver: %s", c.SemVer)
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
		return tagTimestamps[left.Original()].Before(tagTimestamps[right.Original()])
	})
	v := matchedVersions[len(matchedVersions)-1]
	t := v.Original()

	cc, err := checkoutDetachedDwim(repo, t)
	if err != nil {
		return nil, err
	}
	defer cc.Free()
	return buildCommit(cc, "refs/tags/"+t), nil
}

// checkoutDetachedDwim attempts to perform a detached HEAD checkout by first DWIMing the short name
// to get a concrete reference, and then calling checkoutDetachedHEAD.
func checkoutDetachedDwim(repo *git2go.Repository, name string) (*git2go.Commit, error) {
	ref, err := repo.References.Dwim(name)
	if err != nil {
		return nil, fmt.Errorf("unable to find '%s': %w", name, err)
	}
	defer ref.Free()
	c, err := ref.Peel(git2go.ObjectCommit)
	if err != nil {
		return nil, fmt.Errorf("could not get commit for ref '%s': %w", ref.Name(), err)
	}
	defer c.Free()
	cc, err := c.AsCommit()
	if err != nil {
		return nil, fmt.Errorf("could not get commit object for ref '%s': %w", ref.Name(), err)
	}
	defer cc.Free()
	return checkoutDetachedHEAD(repo, cc.Id())
}

// checkoutDetachedHEAD attempts to perform a detached HEAD checkout for the given commit.
func checkoutDetachedHEAD(repo *git2go.Repository, oid *git2go.Oid) (*git2go.Commit, error) {
	cc, err := repo.LookupCommit(oid)
	if err != nil {
		return nil, fmt.Errorf("git commit '%s' not found: %w", oid.String(), err)
	}
	if err = repo.SetHeadDetached(cc.Id()); err != nil {
		cc.Free()
		return nil, fmt.Errorf("could not detach HEAD at '%s': %w", oid.String(), err)
	}
	if err = repo.CheckoutHead(&git2go.CheckoutOptions{
		Strategy: git2go.CheckoutForce,
	}); err != nil {
		cc.Free()
		return nil, fmt.Errorf("git checkout error: %w", err)
	}
	return cc, nil
}

// headCommit returns the current HEAD of the repository, or an error.
func headCommit(repo *git2go.Repository) (*git2go.Commit, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	defer head.Free()
	c, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, err
	}
	return c, nil
}

func buildCommit(c *git2go.Commit, ref string) *git.Commit {
	sig, msg, _ := c.ExtractSignature()
	return &git.Commit{
		Hash:      []byte(c.Id().String()),
		Reference: ref,
		Author:    buildSignature(c.Author()),
		Committer: buildSignature(c.Committer()),
		Signature: sig,
		Encoded:   []byte(msg),
		Message:   c.Message(),
	}
}

func buildSignature(s *git2go.Signature) git.Signature {
	return git.Signature{
		Name:  s.Name,
		Email: s.Email,
		When:  s.When,
	}
}
