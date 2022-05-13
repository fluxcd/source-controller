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
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/fluxcd/pkg/gitutil"
	"github.com/fluxcd/pkg/version"

	"github.com/fluxcd/source-controller/pkg/git"
)

// CheckoutStrategyForOptions returns the git.CheckoutStrategy for the given
// git.CheckoutOptions.
func CheckoutStrategyForOptions(_ context.Context, opts git.CheckoutOptions) git.CheckoutStrategy {
	switch {
	case opts.Commit != "":
		return &CheckoutCommit{Branch: opts.Branch, Commit: opts.Commit, RecurseSubmodules: opts.RecurseSubmodules}
	case opts.SemVer != "":
		return &CheckoutSemVer{SemVer: opts.SemVer, RecurseSubmodules: opts.RecurseSubmodules}
	case opts.Tag != "":
		return &CheckoutTag{Tag: opts.Tag, RecurseSubmodules: opts.RecurseSubmodules, LastRevision: opts.LastRevision}
	default:
		branch := opts.Branch
		if branch == "" {
			branch = git.DefaultBranch
		}
		return &CheckoutBranch{Branch: branch, RecurseSubmodules: opts.RecurseSubmodules, LastRevision: opts.LastRevision}
	}
}

type CheckoutBranch struct {
	Branch            string
	RecurseSubmodules bool
	LastRevision      string
}

func (c *CheckoutBranch) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	authMethod, err := transportAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to construct auth method with options: %w", err)
	}

	ref := plumbing.NewBranchReferenceName(c.Branch)
	// check if previous revision has changed before attempting to clone
	if c.LastRevision != "" {
		currentRevision, err := getLastRevision(ctx, url, ref, opts, authMethod)
		if err != nil {
			return nil, err
		}

		if currentRevision != "" && currentRevision == c.LastRevision {
			// Construct a partial commit with the existing information.
			// Split the revision and take the last part as the hash.
			// Example revision: main/43d7eb9c49cdd49b2494efd481aea1166fc22b67
			var hash git.Hash
			ss := strings.Split(currentRevision, "/")
			if len(ss) > 1 {
				hash = git.Hash(ss[len(ss)-1])
			} else {
				hash = git.Hash(ss[0])
			}
			c := &git.Commit{
				Hash:      hash,
				Reference: plumbing.NewBranchReferenceName(c.Branch).String(),
			}
			return c, nil
		}
	}

	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              authMethod,
		RemoteName:        git.DefaultOrigin,
		ReferenceName:     plumbing.NewBranchReferenceName(c.Branch),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.RecurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          caBundle(opts),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.GoGitError(err))
	}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve HEAD of branch '%s': %w", c.Branch, err)
	}
	cc, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve commit object for HEAD '%s': %w", head.Hash(), err)
	}
	return buildCommitWithRef(cc, ref)
}

func getLastRevision(ctx context.Context, url string, ref plumbing.ReferenceName, opts *git.AuthOptions, authMethod transport.AuthMethod) (string, error) {
	config := &config.RemoteConfig{
		Name: git.DefaultOrigin,
		URLs: []string{url},
	}
	rem := extgogit.NewRemote(memory.NewStorage(), config)
	listOpts := &extgogit.ListOptions{
		Auth: authMethod,
	}
	if opts != nil && opts.CAFile != nil {
		listOpts.CABundle = opts.CAFile
	}
	refs, err := rem.ListContext(ctx, listOpts)
	if err != nil {
		return "", fmt.Errorf("unable to list remote for '%s': %w", url, err)
	}

	currentRevision := filterRefs(refs, ref)
	return currentRevision, nil
}

type CheckoutTag struct {
	Tag               string
	RecurseSubmodules bool
	LastRevision      string
}

func (c *CheckoutTag) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	authMethod, err := transportAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to construct auth method with options: %w", err)
	}
	ref := plumbing.NewTagReferenceName(c.Tag)
	// check if previous revision has changed before attempting to clone
	if c.LastRevision != "" {
		currentRevision, err := getLastRevision(ctx, url, ref, opts, authMethod)
		if err != nil {
			return nil, err
		}

		if currentRevision != "" && currentRevision == c.LastRevision {
			// Construct a partial commit with the existing information.
			// Split the revision and take the last part as the hash.
			// Example revision: 6.1.4/bf09377bfd5d3bcac1e895fa8ce52dc76695c060
			var hash git.Hash
			ss := strings.Split(currentRevision, "/")
			if len(ss) > 1 {
				hash = git.Hash(ss[len(ss)-1])
			} else {
				hash = git.Hash(ss[0])
			}
			c := &git.Commit{
				Hash:      hash,
				Reference: ref.String(),
			}
			return c, nil
		}
	}
	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              authMethod,
		RemoteName:        git.DefaultOrigin,
		ReferenceName:     plumbing.NewTagReferenceName(c.Tag),
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.RecurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          caBundle(opts),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.GoGitError(err))
	}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve HEAD of tag '%s': %w", c.Tag, err)
	}
	cc, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve commit object for HEAD '%s': %w", head.Hash(), err)
	}
	return buildCommitWithRef(cc, ref)
}

type CheckoutCommit struct {
	Branch            string
	Commit            string
	RecurseSubmodules bool
}

func (c *CheckoutCommit) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	authMethod, err := transportAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to construct auth method with options: %w", err)
	}
	cloneOpts := &extgogit.CloneOptions{
		URL:               url,
		Auth:              authMethod,
		RemoteName:        git.DefaultOrigin,
		SingleBranch:      false,
		NoCheckout:        true,
		RecurseSubmodules: recurseSubmodules(c.RecurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.NoTags,
		CABundle:          caBundle(opts),
	}
	if c.Branch != "" {
		cloneOpts.SingleBranch = true
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(c.Branch)
	}
	repo, err := extgogit.PlainCloneContext(ctx, path, false, cloneOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.GoGitError(err))
	}
	w, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to open Git worktree: %w", err)
	}
	cc, err := repo.CommitObject(plumbing.NewHash(c.Commit))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve commit object for '%s': %w", c.Commit, err)
	}
	err = w.Checkout(&extgogit.CheckoutOptions{
		Hash:  cc.Hash,
		Force: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to checkout commit '%s': %w", c.Commit, err)
	}
	return buildCommitWithRef(cc, cloneOpts.ReferenceName)
}

type CheckoutSemVer struct {
	SemVer            string
	RecurseSubmodules bool
}

func (c *CheckoutSemVer) Checkout(ctx context.Context, path, url string, opts *git.AuthOptions) (*git.Commit, error) {
	verConstraint, err := semver.NewConstraint(c.SemVer)
	if err != nil {
		return nil, fmt.Errorf("semver parse error: %w", err)
	}

	authMethod, err := transportAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to construct auth method with options: %w", err)
	}

	repo, err := extgogit.PlainCloneContext(ctx, path, false, &extgogit.CloneOptions{
		URL:               url,
		Auth:              authMethod,
		RemoteName:        git.DefaultOrigin,
		NoCheckout:        false,
		Depth:             1,
		RecurseSubmodules: recurseSubmodules(c.RecurseSubmodules),
		Progress:          nil,
		Tags:              extgogit.AllTags,
		CABundle:          caBundle(opts),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to clone '%s': %w", url, gitutil.GoGitError(err))
	}

	repoTags, err := repo.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	tags := make(map[string]string)
	tagTimestamps := make(map[string]time.Time)
	if err = repoTags.ForEach(func(t *plumbing.Reference) error {
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

	w, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to open Git worktree: %w", err)
	}

	ref := plumbing.NewTagReferenceName(t)
	err = w.Checkout(&extgogit.CheckoutOptions{
		Branch: ref,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to checkout tag '%s': %w", t, err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve HEAD of tag '%s': %w", t, err)
	}
	cc, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve commit object for HEAD '%s': %w", head.Hash(), err)
	}
	return buildCommitWithRef(cc, ref)
}

func buildCommitWithRef(c *object.Commit, ref plumbing.ReferenceName) (*git.Commit, error) {
	if c == nil {
		return nil, errors.New("failed to construct commit: no object")
	}

	// Encode commit components excluding signature into SignedData.
	encoded := &plumbing.MemoryObject{}
	if err := c.EncodeWithoutSignature(encoded); err != nil {
		return nil, fmt.Errorf("failed to encode commit '%s': %w", c.Hash, err)
	}
	reader, err := encoded.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to encode commit '%s': %w", c.Hash, err)
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encoded commit '%s': %w", c.Hash, err)
	}
	return &git.Commit{
		Hash:      []byte(c.Hash.String()),
		Reference: ref.String(),
		Author:    buildSignature(c.Author),
		Committer: buildSignature(c.Committer),
		Signature: c.PGPSignature,
		Encoded:   b,
		Message:   c.Message,
	}, nil
}

func buildSignature(s object.Signature) git.Signature {
	return git.Signature{
		Name:  s.Name,
		Email: s.Email,
		When:  s.When,
	}
}

func recurseSubmodules(recurse bool) extgogit.SubmoduleRescursivity {
	if recurse {
		return extgogit.DefaultSubmoduleRecursionDepth
	}
	return extgogit.NoRecurseSubmodules
}

func filterRefs(refs []*plumbing.Reference, currentRef plumbing.ReferenceName) string {
	for _, ref := range refs {
		if ref.Name().String() == currentRef.String() {
			return fmt.Sprintf("%s/%s", currentRef.Short(), ref.Hash().String())
		}
	}

	return ""
}
