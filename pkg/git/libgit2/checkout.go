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
	git2go "github.com/libgit2/git2go/v33"

	"github.com/fluxcd/pkg/gitutil"
	"github.com/fluxcd/pkg/version"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
)

// CheckoutStrategyForOptions returns the git.CheckoutStrategy for the given
// git.CheckoutOptions.
func CheckoutStrategyForOptions(ctx context.Context, opt git.CheckoutOptions) git.CheckoutStrategy {
	if opt.RecurseSubmodules {
		logr.FromContextOrDiscard(ctx).Info(fmt.Sprintf("git submodule recursion not supported by implementation '%s'", Implementation))
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
		return &CheckoutBranch{
			Branch:       branch,
			LastRevision: opt.LastRevision,
		}
	}
}

type CheckoutBranch struct {
	Branch       string
	LastRevision string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	repo, remote, err := getBlankRepoAndRemote(ctx, path, url, opts)

	if err != nil {
		return nil, err
	}
	defer repo.Free()
	defer remote.Free()
	defer remote.Disconnect()

	// When the last observed revision is set, check whether it is still
	// the same at the remote branch. If so, short-circuit the clone operation here.
	if c.LastRevision != "" {
		heads, err := remote.Ls(c.Branch)
		if err != nil {
			return nil, fmt.Errorf("unable to remote ls for '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
		}
		if len(heads) > 0 {
			currentRevision := fmt.Sprintf("%s/%s", c.Branch, heads[0].Id.String())
			if currentRevision == c.LastRevision {
				return nil, git.NoChangesError{
					Message:          "no changes since last reconciliation",
					ObservedRevision: currentRevision,
				}
			}
		}
	}

	// Limit the fetch operation to the specific branch, to decrease network usage.
	err = remote.Fetch([]string{c.Branch},
		&git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsNone,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
		"")
	if err != nil {
		return nil, fmt.Errorf("unable to fetch remote '%s': %w",
			managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}

	branch, err := repo.References.Lookup(fmt.Sprintf("refs/remotes/origin/%s", c.Branch))
	if err != nil {
		return nil, fmt.Errorf("unable to lookup branch '%s' for '%s': %w",
			c.Branch, managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}
	defer branch.Free()

	upstreamCommit, err := repo.LookupCommit(branch.Target())
	if err != nil {
		return nil, fmt.Errorf("unable to lookup commit '%s' for '%s': %w",
			c.Branch, managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}
	defer upstreamCommit.Free()

	// Once the index has been updated with Fetch, and we know the tip commit,
	// a hard reset can be used to align the local worktree with the remote branch's.
	err = repo.ResetToCommit(upstreamCommit, git2go.ResetHard, &git2go.CheckoutOptions{
		Strategy: git2go.CheckoutForce,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to hard reset to commit for '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}

	// Use the current worktree's head as reference for the commit to be returned.
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("git resolve HEAD error: %w", err)
	}
	defer head.Free()

	cc, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, fmt.Errorf("failed to lookup HEAD commit '%s' for branch '%s': %w", head.Target(), c.Branch, err)
	}
	defer cc.Free()

	return buildCommit(cc, "refs/heads/"+c.Branch), nil
}

type CheckoutTag struct {
	Tag          string
	LastRevision string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	repo, remote, err := getBlankRepoAndRemote(ctx, path, url, opts)

	if err != nil {
		return nil, err
	}

	defer repo.Free()
	defer remote.Free()
	defer remote.Disconnect()

	if c.LastRevision != "" {
		heads, err := remote.Ls(c.Tag)
		if err != nil {
			return nil, fmt.Errorf("unable to remote ls for '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
		}
		if len(heads) > 0 {
			currentRevision := fmt.Sprintf("%s/%s", c.Tag, heads[0].Id.String())
			var same bool
			if currentRevision == c.LastRevision {
				same = true
			} else if len(heads) > 1 {
				currentAnnotatedRevision := fmt.Sprintf("%s/%s", c.Tag, heads[1].Id.String())
				if currentAnnotatedRevision == c.LastRevision {
					same = true
				}
			}
			if same {
				return nil, git.NoChangesError{
					Message:          "no changes since last reconciliation",
					ObservedRevision: currentRevision,
				}
			}
		}
	}

	err = remote.Fetch([]string{c.Tag},
		&git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsAuto,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
		"")

	if err != nil {
		return nil, fmt.Errorf("unable to fetch remote '%s': %w",
			managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}

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
	repo, err := safeClone(url, path, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsNone,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
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

	repo, err := safeClone(url, path, &git2go.CloneOptions{
		FetchOptions: git2go.FetchOptions{
			DownloadTags:    git2go.DownloadTagsAll,
			RemoteCallbacks: RemoteCallbacks(ctx, opts),
			ProxyOptions:    git2go.ProxyOptions{Type: git2go.ProxyTypeAuto},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
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

// safeClone wraps git2go calls with panic recovering logic, ensuring
// a predictable execution path for callers.
func safeClone(url, path string, cloneOpts *git2go.CloneOptions) (repo *git2go.Repository, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from git2go panic: %v", r)
		}
	}()

	repo, err = git2go.Clone(url, path, cloneOpts)
	return
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

// getBlankRepoAndRemote returns a newly initialized repository, and a remote connected to the provided url.
// Callers must make sure to call the below defer statements:
//	defer repo.Free()
//	defer remote.Free()
//	defer remote.Disconnect()
func getBlankRepoAndRemote(ctx context.Context, path, url string, opts *git.AuthOptions) (*git2go.Repository, *git2go.Remote, error) {
	repo, err := git2go.InitRepository(path, false)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to init repository for '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}

	remote, err := repo.Remotes.Create("origin", url)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create remote for '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}

	callBacks := RemoteCallbacks(ctx, opts)
	err = remote.ConnectFetch(&callBacks, &git2go.ProxyOptions{Type: git2go.ProxyTypeAuto}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch-connect to remote '%s': %w", managed.EffectiveURL(url), gitutil.LibGit2Error(err))
	}
	return repo, remote, nil
}
