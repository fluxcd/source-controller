/*
Copyright 2026 The Flux authors

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

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"

	extgogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/runtime/conditions"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
)

const (
	// forwardOnlyCloneDepth is the number of commits cloned when forward-only
	// verification has a baseline to look for.
	forwardOnlyCloneDepth = 100

	// forwardOnlyDeepCloneDepth is the number of commits cloned into a fresh
	// directory when the baseline is not within forwardOnlyCloneDepth. A
	// baseline further away is rejected, which bounds the memory, traffic
	// and time a reference pointed at an old commit can cost per attempt.
	forwardOnlyDeepCloneDepth = 500

	// maxAncestryVisits bounds the number of commits findAncestor loads. A
	// clone depth counts generations, so a merge-heavy clone holds more
	// commits than its depth; the bound mainly guards the full-history
	// clones used for commits and pull request references.
	maxAncestryVisits = 100_000

	// nonFastForwardRevisionReason signals that a revision was rejected by
	// forward-only verification because it does not descend from the last
	// verified revision.
	nonFastForwardRevisionReason = "NonFastForwardRevision"
)

// ancestryResult is the outcome of searching the history of a commit for an
// ancestor.
type ancestryResult int

const (
	// ancestryFound means the ancestor was reached.
	ancestryFound ancestryResult = iota
	// ancestryNotFound means the complete reachable history was traversed
	// without reaching the ancestor.
	ancestryNotFound
	// ancestryTruncated means the traversal stopped at a shallow boundary or
	// at the visit limit before reaching the ancestor, which may exist beyond
	// the available history.
	ancestryTruncated
)

// forwardOnlyRejection is a revision rejected by forward-only verification. It
// is cached per object so that retries repeat the rejection without
// inspecting the history while the remote reference still points to the
// rejected revision, the object is unchanged and the baseline is the same.
type forwardOnlyRejection struct {
	uid        types.UID
	generation int64
	baseline   string
	revision   string
	message    string
}

// cachedForwardOnlyRejection returns the cached rejection for the object if
// it still applies.
func (r *GitRepositoryReconciler) cachedForwardOnlyRejection(obj *sourcev1.GitRepository) (forwardOnlyRejection, bool) {
	v, ok := r.rejectedRevisions.Load(client.ObjectKeyFromObject(obj))
	if !ok {
		return forwardOnlyRejection{}, false
	}
	rej, ok := v.(forwardOnlyRejection)
	if !ok || !forwardOnlyEnabled(obj) || rej.uid != obj.UID || rej.generation != obj.Generation ||
		rej.baseline != obj.Status.SourceVerificationRevision {
		return forwardOnlyRejection{}, false
	}
	return rej, true
}

// forwardOnlyEnabled returns whether forward-only verification is configured.
func forwardOnlyEnabled(obj *sourcev1.GitRepository) bool {
	return obj.Spec.Verification != nil && obj.Spec.Verification.Mode != "" && obj.Spec.Verification.ForwardOnly
}

// isSemVerReference returns whether the reference is resolved by a semver
// range, following the precedence of the Git client: commit, name and tag take
// precedence over semver.
func isSemVerReference(ref *sourcev1.GitRepositoryRef) bool {
	return ref != nil && ref.SemVer != "" && ref.Commit == "" && ref.Name == "" && ref.Tag == ""
}

// cloneDepthApplies returns whether the clone of the configured reference
// honours a clone depth. Branches and tags do, directly or through a reference
// name; a commit, and a reference name that is neither a branch nor a tag, are
// cloned with their full history.
func cloneDepthApplies(ref *sourcev1.GitRepositoryRef) bool {
	switch {
	case ref == nil:
		return true
	case ref.Commit != "":
		return false
	case ref.Name != "":
		name := plumbing.ReferenceName(ref.Name)
		return name.IsBranch() || name.IsTag()
	default:
		return true
	}
}

// findAncestor reports whether ancestor is reachable from head by walking the
// parent links breadth-first, loading at most limit commits. Commits listed in
// shallow are shallow boundaries whose parents are not available; a missing
// parent object is treated the same way.
func findAncestor(s storer.EncodedObjectStorer, shallow []plumbing.Hash, head, ancestor plumbing.Hash, limit int) (ancestryResult, error) {
	boundary := make(map[plumbing.Hash]struct{}, len(shallow))
	for _, h := range shallow {
		boundary[h] = struct{}{}
	}

	visited := map[plumbing.Hash]struct{}{head: {}}
	queue := []plumbing.Hash{head}
	truncated := false
	for visits := 0; len(queue) > 0; visits++ {
		h := queue[0]
		queue = queue[1:]
		if h == ancestor {
			return ancestryFound, nil
		}
		if visits >= limit {
			return ancestryTruncated, nil
		}
		if _, ok := boundary[h]; ok {
			truncated = true
			continue
		}
		c, err := object.GetCommit(s, h)
		if err != nil {
			if errors.Is(err, plumbing.ErrObjectNotFound) {
				truncated = true
				continue
			}
			return ancestryNotFound, fmt.Errorf("unable to read commit '%s': %w", h, err)
		}
		for _, p := range c.ParentHashes {
			if _, ok := visited[p]; ok {
				continue
			}
			visited[p] = struct{}{}
			queue = append(queue, p)
		}
	}
	if truncated {
		return ancestryTruncated, nil
	}
	return ancestryNotFound, nil
}

// isDescendant opens the Git repository checked out at dir and reports whether
// head descends from ancestor within the available history.
func isDescendant(dir string, head, ancestor plumbing.Hash) (ancestryResult, error) {
	repo, err := extgogit.PlainOpen(dir)
	if err != nil {
		return ancestryNotFound, fmt.Errorf("unable to open repository: %w", err)
	}
	shallow, err := repo.Storer.Shallow()
	if err != nil {
		return ancestryNotFound, fmt.Errorf("unable to read shallow boundaries: %w", err)
	}
	return findAncestor(repo.Storer, shallow, head, ancestor, maxAncestryVisits)
}

// verifySource verifies the signature of the given commit and, when
// forward-only verification is enabled, that it descends from the last
// verified revision. On success it records the revision as the new baseline.
// A rejection by the history check leaves the verification status of the
// current Artifact untouched.
func (r *GitRepositoryReconciler) verifySource(ctx context.Context, obj *sourcev1.GitRepository,
	authOpts *git.AuthOptions, proxyOpts *transport.ProxyOptions, dir string, commit *git.Commit, force bool) (sreconcile.Result, error) {
	prevMode, prevFingerprint := obj.Status.SourceVerificationMode, obj.Status.SourceVerificationFingerprint
	if result, err := r.verifySignature(ctx, obj, *commit); err != nil || result == sreconcile.ResultEmpty {
		return result, err
	}
	result, err := r.verifyHistory(ctx, obj, authOpts, proxyOpts, dir, commit, force)
	if err != nil || result == sreconcile.ResultEmpty {
		obj.Status.SourceVerificationMode, obj.Status.SourceVerificationFingerprint = prevMode, prevFingerprint
	}
	return result, err
}

// verifyHistory enforces forward-only verification for a commit whose
// signature has been verified, and records it as the last verified revision.
// A force request skips the history check and makes the commit the new
// baseline.
func (r *GitRepositoryReconciler) verifyHistory(ctx context.Context, obj *sourcev1.GitRepository,
	authOpts *git.AuthOptions, proxyOpts *transport.ProxyOptions, dir string, commit *git.Commit, force bool) (sreconcile.Result, error) {
	if obj.Spec.Verification == nil || obj.Spec.Verification.Mode == "" {
		return sreconcile.ResultSuccess, nil
	}

	baseline := obj.Status.SourceVerificationRevision
	forwardOnly := obj.Spec.Verification.ForwardOnly
	if forwardOnly && baseline != "" && !force {
		if result, err := r.checkAncestry(ctx, obj, authOpts, proxyOpts, dir, commit, baseline); err != nil || result == sreconcile.ResultEmpty {
			return result, err
		}
	}

	revision := commitReference(obj, commit)
	obj.Status.SourceVerificationRevision = revision
	r.rejectedRevisions.Delete(client.ObjectKeyFromObject(obj))

	if forwardOnly {
		switch {
		case force && baseline != "":
			sreconcile.EventLogf(ctx, r, obj, corev1.EventTypeNormal, meta.SucceededReason, sourcev1.ActionVerifySource,
				"forward-only baseline reset to '%s' by force request", revision)
		case baseline == "":
			msg := fmt.Sprintf("forward-only baseline established at '%s'", revision)
			conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason, "%s\n%s",
				conditions.GetMessage(obj, sourcev1.SourceVerifiedCondition), msg)
			sreconcile.EventLogf(ctx, r, obj, corev1.EventTypeNormal, meta.SucceededReason, sourcev1.ActionVerifySource, "%s", msg)
		}
	}
	return sreconcile.ResultSuccess, nil
}

// checkAncestry rejects the commit unless the baseline revision is found in its
// history. When the reference honours a clone depth, dir holds the last
// forwardOnlyCloneDepth commits; if the baseline is beyond them, the directory
// is cleared and the reference is cloned again with forwardOnlyDeepCloneDepth
// commits, verifying the signature again if the remote HEAD moved in between.
func (r *GitRepositoryReconciler) checkAncestry(ctx context.Context, obj *sourcev1.GitRepository,
	authOpts *git.AuthOptions, proxyOpts *transport.ProxyOptions, dir string, commit *git.Commit, baseline string) (sreconcile.Result, error) {
	const hint = "request a forced reconciliation with the reconcile.fluxcd.io/forceAt annotation to accept it as the new baseline"
	ancestor := plumbing.NewHash(git.ExtractHashFromRevision(baseline).String())
	if ancestor.IsZero() {
		return r.rejectRevision(obj, baseline, commitReference(obj, commit), fmt.Sprintf(
			"revision '%s' could not be verified against the last verified revision '%s', which has no valid commit hash; %s",
			commitReference(obj, commit), baseline, hint))
	}
	depthApplies := cloneDepthApplies(obj.Spec.Reference)

	res, err := isDescendant(dir, plumbing.NewHash(commit.Hash.String()), ancestor)
	if err == nil && res == ancestryTruncated && depthApplies {
		if err := os.RemoveAll(dir); err == nil {
			err = os.MkdirAll(dir, 0o700)
		}
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to reset temporary working directory: %w", err),
				sourcev1.DirCreationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
		c, err := r.gitCheckout(ctx, obj, authOpts, proxyOpts, dir, false, forwardOnlyDeepCloneDepth)
		if err != nil {
			return sreconcile.ResultEmpty, err
		}
		if c == nil {
			e := serror.NewGeneric(
				errors.New("git repository is empty"),
				"EmptyGitRepository",
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
		if err := r.validateSparseCheckoutPaths(obj, dir); err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to sparse checkout directories : %w", err),
				sourcev1.GitOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
		if c.Hash.String() != commit.Hash.String() {
			if result, err := r.verifySignature(ctx, obj, *c); err != nil || result == sreconcile.ResultEmpty {
				return result, err
			}
		}
		*commit = *c
		res, err = isDescendant(dir, plumbing.NewHash(commit.Hash.String()), ancestor)
	}
	revision := commitReference(obj, commit)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to inspect the history of revision '%s': %w", revision, err),
			sourcev1.GitOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	switch {
	case res == ancestryFound:
		return sreconcile.ResultSuccess, nil
	case res == ancestryTruncated && depthApplies:
		return r.rejectRevision(obj, baseline, revision, fmt.Sprintf(
			"revision '%s' could not be verified as a descendant of the last verified revision '%s': the latter was not found within the last %d commits; %s",
			revision, baseline, forwardOnlyDeepCloneDepth, hint))
	case res == ancestryTruncated:
		return r.rejectRevision(obj, baseline, revision, fmt.Sprintf(
			"revision '%s' could not be verified as a descendant of the last verified revision '%s': the latter was not found among the first %d commits of its history; %s",
			revision, baseline, maxAncestryVisits, hint))
	default:
		return r.rejectRevision(obj, baseline, revision, fmt.Sprintf(
			"revision '%s' is not a descendant of the last verified revision '%s'; %s",
			revision, baseline, hint))
	}
}

// rejectRevision records the rejection of a revision by forward-only
// verification in the status and in the rejection cache.
func (r *GitRepositoryReconciler) rejectRevision(obj *sourcev1.GitRepository, baseline, revision, msg string) (sreconcile.Result, error) {
	e := serror.NewGeneric(errors.New(msg), nonFastForwardRevisionReason)
	conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, "%s", e)
	r.rejectedRevisions.Store(client.ObjectKeyFromObject(obj), forwardOnlyRejection{
		uid:        obj.UID,
		generation: obj.Generation,
		baseline:   baseline,
		revision:   revision,
		message:    msg,
	})
	return sreconcile.ResultEmpty, e
}
