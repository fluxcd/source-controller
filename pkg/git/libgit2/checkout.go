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
	git2go "github.com/libgit2/git2go/v31"

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
	defer head.Free()
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
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, gitutil.LibGit2Error(err))
	}
	commit, err := checkoutDetachedDwim(repo, c.tag)
	if err != nil {
		return nil, "", err
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.tag, commit.Id().String()), nil
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
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, gitutil.LibGit2Error(err))
	}

	oid, err := git2go.NewOid(c.commit)
	if err != nil {
		return nil, "", fmt.Errorf("could not create oid for '%s': %w", c.commit, err)
	}
	commit, err := checkoutDetachedHEAD(repo, oid)
	if err != nil {
		return nil, "", fmt.Errorf("git checkout error: %w", err)
	}
	return &Commit{commit}, fmt.Sprintf("%s/%s", c.branch, commit.Id().String()), nil
}

type CheckoutSemVer struct {
	semVer string
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, auth *git.Auth) (git.Commit, string, error) {
	verConstraint, err := semver.NewConstraint(c.semVer)
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
		return nil, "", fmt.Errorf("unable to clone '%s', error: %w", url, gitutil.LibGit2Error(err))
	}

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
		return nil, "", err
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

	commit, err := checkoutDetachedDwim(repo, t)
	return &Commit{commit}, fmt.Sprintf("%s/%s", t, commit.Id().String()), nil
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
	commit, err := c.AsCommit()
	if err != nil {
		return nil, fmt.Errorf("could not get commit object for ref '%s': %w", ref.Name(), err)
	}
	defer commit.Free()
	return checkoutDetachedHEAD(repo, commit.Id())
}

// checkoutDetachedHEAD attempts to perform a detached HEAD checkout for the given commit.
func checkoutDetachedHEAD(repo *git2go.Repository, oid *git2go.Oid) (*git2go.Commit, error) {
	commit, err := repo.LookupCommit(oid)
	if err != nil {
		return nil, fmt.Errorf("git commit '%s' not found: %w", oid.String(), err)
	}
	if err = repo.SetHeadDetached(commit.Id()); err != nil {
		commit.Free()
		return nil, fmt.Errorf("could not detach HEAD at '%s': %w", oid.String(), err)
	}
	if err = repo.CheckoutHead(&git2go.CheckoutOptions{
		Strategy: git2go.CheckoutForce,
	}); err != nil {
		commit.Free()
		return nil, fmt.Errorf("git checkout error: %w", err)
	}
	return commit, nil
}

// headCommit returns the current HEAD of the repository, or an error.
func headCommit(repo *git2go.Repository) (*git2go.Commit, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	defer head.Free()

	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, err
	}

	return commit, nil
}
