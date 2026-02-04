/*
Copyright 2022 The Flux authors

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
	cryptotls "crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/cache"
	"github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	rreconcile "github.com/fluxcd/pkg/runtime/reconcile"
	"github.com/fluxcd/pkg/runtime/secrets"
	"github.com/fluxcd/pkg/sourceignore"
	"github.com/fluxcd/pkg/tar"
	"github.com/fluxcd/pkg/version"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	serror "github.com/werf/nelm-source-controller/internal/error"
	soci "github.com/werf/nelm-source-controller/internal/oci"
	scosign "github.com/werf/nelm-source-controller/internal/oci/cosign"
	"github.com/werf/nelm-source-controller/internal/oci/notation"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
	"github.com/werf/nelm-source-controller/internal/util"
)

// ociRepositoryReadyCondition contains the information required to summarize a
// v1.OCIRepository Ready Condition.
var ociRepositoryReadyCondition = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		sourcev1.SourceVerifiedCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		sourcev1.SourceVerifiedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// ociRepositoryFailConditions contains the conditions that represent a failure.
var ociRepositoryFailConditions = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.StorageOperationFailedCondition,
}

type filterFunc func(tags []string) ([]string, error)

type invalidOCIURLError struct {
	err error
}

func (e invalidOCIURLError) Error() string {
	return e.err.Error()
}

// ociRepositoryReconcileFunc is the function type for all the v1.OCIRepository
// (sub)reconcile functions. The type implementations are grouped and
// executed serially to perform the complete reconcile of the object.
type ociRepositoryReconcileFunc func(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.OCIRepository, metadata *meta.Artifact, dir string) (sreconcile.Result, error)

// OCIRepositoryReconciler reconciles a v1.OCIRepository object
type OCIRepositoryReconciler struct {
	client.Client
	helper.Metrics
	kuberecorder.EventRecorder

	Storage           *storage.Storage
	ControllerName    string
	TokenCache        *cache.TokenCache
	requeueDependency time.Duration

	patchOptions []patch.Option
}

type OCIRepositoryReconcilerOptions struct {
	DependencyRequeueInterval time.Duration
	RateLimiter               workqueue.TypedRateLimiter[reconcile.Request]
}

// SetupWithManager sets up the controller with the Manager.
func (r *OCIRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, OCIRepositoryReconcilerOptions{})
}

func (r *OCIRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts OCIRepositoryReconcilerOptions) error {
	r.patchOptions = getPatchOptions(ociRepositoryReadyCondition.Owned, r.ControllerName)

	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.OCIRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{
			RateLimiter: opts.RateLimiter,
		}).
		Complete(r)
}

// +kubebuilder:rbac:groups=source.werf.io,resources=ocirepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.werf.io,resources=ocirepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.werf.io,resources=ocirepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

func (r *OCIRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the OCIRepository
	obj := &sourcev1.OCIRepository{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Initialize the patch helper with the current version of the object.
	serialPatcher := patch.NewSerialPatcher(obj, r.Client)

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object and status after each reconciliation
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, serialPatcher)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(ociRepositoryReadyCondition),
			summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.ErrorActionHandler,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
				RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
			}),
			summarize.WithPatchFieldOwner(r.ControllerName),
		}
		result, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

		// Always record duration metrics.
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Examine if the object is under deletion.
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		recResult, retErr = r.reconcileDelete(ctx, obj)
		return
	}

	// Add finalizer first if not exist to avoid the race condition between init
	// and delete.
	// Note: Finalizers in general can only be added when the deletionTimestamp
	// is not set.
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return
	}

	// Return if the object is suspended.
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		recResult, retErr = sreconcile.ResultEmpty, nil
		return
	}

	// Reconcile actual object
	reconcilers := []ociRepositoryReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, serialPatcher, obj, reconcilers)
	return
}

// reconcile iterates through the ociRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *OCIRepositoryReconciler) reconcile(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.OCIRepository, reconcilers []ociRepositoryReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason, "reconciliation in progress")

	var reconcileAtVal string
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		reconcileAtVal = v
	}

	// Persist reconciling status if generation differs or reconciliation is
	// requested.
	switch {
	case obj.Generation != obj.Status.ObservedGeneration:
		rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason,
			"processing object: new generation %d -> %d", obj.Status.ObservedGeneration, obj.Generation)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	case reconcileAtVal != obj.Status.GetLastHandledReconcileRequest():
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	}

	// Create temp working dir
	tmpDir, err := util.TempDirForObj("", obj)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create temporary working directory: %w", err),
			sourcev1.DirCreationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	defer func() {
		if err = os.RemoveAll(tmpDir); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to remove temporary working directory")
		}
	}()
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)

	var (
		res      sreconcile.Result
		resErr   error
		metadata = meta.Artifact{}
	)

	// Run the sub-reconcilers and build the result of reconciliation.
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, sp, obj, &metadata, tmpDir)
		// Exit immediately on ResultRequeue.
		if recResult == sreconcile.ResultRequeue {
			return sreconcile.ResultRequeue, nil
		}
		// If an error is received, prioritize the returned results because an
		// error also means immediate requeue.
		if err != nil {
			resErr = err
			res = recResult
			break
		}
		// Prioritize requeue request in the result.
		res = sreconcile.LowestRequeuingResult(res, recResult)
	}

	r.notify(ctx, oldObj, obj, res, resErr)

	return res, resErr
}

// reconcileSource fetches the upstream OCI artifact metadata and content.
// If this fails, it records v1.FetchFailedCondition=True on the object and returns early.
func (r *OCIRepositoryReconciler) reconcileSource(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.OCIRepository, metadata *meta.Artifact, dir string) (sreconcile.Result, error) {
	var authenticator authn.Authenticator

	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	// Remove previously failed source verification status conditions. The
	// failing verification should be recalculated. But an existing successful
	// verification need not be removed as it indicates verification of previous
	// version.
	if conditions.IsFalse(obj, sourcev1.SourceVerifiedCondition) {
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
	}

	// Generate the registry credential keychain either from static credentials or using cloud OIDC
	keychain, err := r.keychain(ctx, obj)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to get credential: %w", err),
			sourcev1.AuthenticationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	var proxyURL *url.URL
	if obj.Spec.ProxySecretRef != nil {
		var err error
		proxyURL, err = secrets.ProxyURLFromSecretRef(ctx, r.Client, types.NamespacedName{
			Name:      obj.Spec.ProxySecretRef.Name,
			Namespace: obj.GetNamespace(),
		})
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to get proxy address: %w", err),
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}

	if _, ok := keychain.(soci.Anonymous); obj.Spec.Provider != "" && obj.Spec.Provider != sourcev1.GenericOCIProvider && ok {
		opts := []auth.Option{
			auth.WithClient(r.Client),
			auth.WithServiceAccountNamespace(obj.GetNamespace()),
		}

		if obj.Spec.ServiceAccountName != "" {
			// Check object-level workload identity feature gate.
			if !auth.IsObjectLevelWorkloadIdentityEnabled() {
				const gate = auth.FeatureGateObjectLevelWorkloadIdentity
				const msgFmt = "to use spec.serviceAccountName for provider authentication please enable the %s feature gate in the controller"
				err := fmt.Errorf(msgFmt, gate)
				return sreconcile.ResultEmpty, serror.NewStalling(err, meta.FeatureGateDisabledReason)
			}
			// Set ServiceAccountName only if explicitly specified
			opts = append(opts, auth.WithServiceAccountName(obj.Spec.ServiceAccountName))
		}
		if r.TokenCache != nil {
			involvedObject := cache.InvolvedObject{
				Kind:      sourcev1.OCIRepositoryKind,
				Name:      obj.GetName(),
				Namespace: obj.GetNamespace(),
				Operation: cache.OperationReconcile,
			}
			opts = append(opts, auth.WithCache(*r.TokenCache, involvedObject))
		}
		if proxyURL != nil {
			opts = append(opts, auth.WithProxyURL(*proxyURL))
		}
		var authErr error
		authenticator, authErr = soci.OIDCAuth(ctxTimeout, obj.Spec.URL, obj.Spec.Provider, opts...)
		if authErr != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to get credential from %s: %w", obj.Spec.Provider, authErr),
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}

	// Generate the transport for remote operations
	transport, err := r.transport(ctx, obj, proxyURL)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to generate transport for '%s': %w", obj.Spec.URL, err),
			sourcev1.AuthenticationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	opts := makeRemoteOptions(ctx, transport, keychain, authenticator)

	// Determine which artifact revision to pull
	ref, err := r.getArtifactRef(obj, opts)
	if err != nil {
		if _, ok := err.(invalidOCIURLError); ok {
			e := serror.NewStalling(
				fmt.Errorf("URL validation failed for '%s': %w", obj.Spec.URL, err),
				sourcev1.URLInvalidReason)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}

		e := serror.NewGeneric(
			fmt.Errorf("failed to determine the artifact tag for '%s': %w", obj.Spec.URL, err),
			sourcev1.ReadOperationFailedReason)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Get the upstream revision from the artifact digest
	// TODO: getRevision resolves the digest, which may change before image is fetched, so it should probaly update ref
	revision, err := r.getRevision(ref, opts)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to determine artifact digest: %w", err),
			sourcev1.OCIPullFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	metaArtifact := &meta.Artifact{Revision: revision}
	metaArtifact.DeepCopyInto(metadata)

	// Mark observations about the revision on the object
	defer func() {
		if !obj.GetArtifact().HasRevision(revision) {
			message := fmt.Sprintf("new revision '%s' for '%s'", revision, ref)
			if obj.GetArtifact() != nil {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "%s", message)
			}
			rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "building artifact: %s", message)
			if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "failed to patch")
				return
			}
		}
	}()

	// Verify artifact if:
	// - the upstream digest differs from the one in storage (revision drift)
	// - the OCIRepository spec has changed (generation drift)
	// - the previous reconciliation resulted in a failed artifact verification (retry with exponential backoff)
	if obj.Spec.Verify == nil {
		// Remove old observations if verification was disabled
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
	} else if !obj.GetArtifact().HasRevision(revision) ||
		conditions.GetObservedGeneration(obj, sourcev1.SourceVerifiedCondition) != obj.Generation ||
		conditions.IsFalse(obj, sourcev1.SourceVerifiedCondition) {

		result, err := r.verifySignature(ctx, obj, ref, keychain, authenticator, transport, opts...)
		if err != nil {
			provider := obj.Spec.Verify.Provider
			if obj.Spec.Verify.SecretRef == nil && obj.Spec.Verify.Provider == "cosign" {
				provider = fmt.Sprintf("%s keyless", provider)
			}
			e := serror.NewGeneric(
				fmt.Errorf("failed to verify the signature using provider '%s': %w", provider, err),
				sourcev1.VerificationError,
			)
			conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}

		if result == soci.VerificationResultSuccess {
			conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision %s", revision)
		}
	}

	// Skip pulling if the artifact revision and the source configuration has
	// not changed.
	if obj.GetArtifact().HasRevision(revision) && !ociContentConfigChanged(obj) {
		conditions.Delete(obj, sourcev1.FetchFailedCondition)
		return sreconcile.ResultSuccess, nil
	}

	// Pull artifact from the remote container registry
	img, err := remote.Image(ref, opts...)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to pull artifact from '%s': %w", obj.Spec.URL, err),
			sourcev1.OCIPullFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Copy the OCI annotations to the internal artifact metadata
	manifest, err := img.Manifest()
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to parse artifact manifest: %w", err),
			sourcev1.OCILayerOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	metadata.Metadata = manifest.Annotations

	// Extract the compressed content from the selected layer
	blob, err := r.selectLayer(obj, img)
	if err != nil {
		e := serror.NewGeneric(err, sourcev1.OCILayerOperationFailedReason)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Persist layer content to storage using the specified operation
	switch obj.GetLayerOperation() {
	case sourcev1.OCILayerExtract:
		if err = tar.Untar(blob, dir, tar.WithMaxUntarSize(-1), tar.WithSkipSymlinks()); err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to extract layer contents from artifact: %w", err),
				sourcev1.OCILayerOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	case sourcev1.OCILayerCopy:
		metadata.Path = fmt.Sprintf("%s.tgz", r.digestFromRevision(metadata.Revision))
		file, err := os.Create(filepath.Join(dir, metadata.Path))
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to create file to copy layer to: %w", err),
				sourcev1.OCILayerOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
		defer file.Close()

		_, err = io.Copy(file, blob)
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to copy layer from artifact: %w", err),
				sourcev1.OCILayerOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	default:
		e := serror.NewGeneric(
			fmt.Errorf("unsupported layer operation: %s", obj.GetLayerOperation()),
			sourcev1.OCILayerOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	conditions.Delete(obj, sourcev1.FetchFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// selectLayer finds the matching layer and returns its compressed contents.
// If no layer selector was provided, we pick the first layer from the OCI artifact.
func (r *OCIRepositoryReconciler) selectLayer(obj *sourcev1.OCIRepository, image gcrv1.Image) (io.ReadCloser, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to parse artifact layers: %w", err)
	}

	if len(layers) < 1 {
		return nil, fmt.Errorf("no layers found in artifact")
	}

	var layer gcrv1.Layer
	switch {
	case obj.GetLayerMediaType() != "":
		var found bool
		for i, l := range layers {
			md, err := l.MediaType()
			if err != nil {
				return nil, fmt.Errorf("failed to determine the media type of layer[%v] from artifact: %w", i, err)
			}
			if string(md) == obj.GetLayerMediaType() {
				layer = layers[i]
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("failed to find layer with media type '%s' in artifact", obj.GetLayerMediaType())
		}
	default:
		layer = layers[0]
	}

	blob, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("failed to extract the first layer from artifact: %w", err)
	}

	return blob, nil
}

// getRevision fetches the upstream digest, returning the revision in the
// format '<tag>@<digest>'.
func (r *OCIRepositoryReconciler) getRevision(ref name.Reference, options []remote.Option) (string, error) {
	switch ref := ref.(type) {
	case name.Digest:
		digest, err := gcrv1.NewHash(ref.DigestStr())
		if err != nil {
			return "", err
		}
		return digest.String(), nil
	case name.Tag:
		var digest gcrv1.Hash

		desc, err := remote.Head(ref, options...)
		if err == nil {
			digest = desc.Digest
		} else {
			rdesc, err := remote.Get(ref, options...)
			if err != nil {
				return "", err
			}
			digest = rdesc.Descriptor.Digest
		}
		return fmt.Sprintf("%s@%s", ref.TagStr(), digest.String()), nil
	default:
		return "", fmt.Errorf("unsupported reference type: %T", ref)
	}
}

// digestFromRevision extracts the digest from the revision string.
func (r *OCIRepositoryReconciler) digestFromRevision(revision string) string {
	parts := strings.Split(revision, "@")
	return parts[len(parts)-1]
}

// verifySignature verifies the authenticity of the given image reference URL.
// It supports two different verification providers: cosign and notation.
// First, it tries to use a key if a Secret with a valid public key is provided.
// If not, when using cosign it falls back to a keyless approach for verification.
// When notation is used, a trust policy is required to verify the image.
// The verification result is returned as a VerificationResult and any error encountered.
func (r *OCIRepositoryReconciler) verifySignature(ctx context.Context, obj *sourcev1.OCIRepository,
	ref name.Reference, keychain authn.Keychain, auth authn.Authenticator,
	transport *http.Transport, opt ...remote.Option) (soci.VerificationResult, error) {

	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	provider := obj.Spec.Verify.Provider
	switch provider {
	case "cosign":
		defaultCosignOciOpts := []scosign.Options{
			scosign.WithRemoteOptions(opt...),
		}

		// get the public keys from the given secret
		if secretRef := obj.Spec.Verify.SecretRef; secretRef != nil {

			verifySecret := types.NamespacedName{
				Namespace: obj.Namespace,
				Name:      secretRef.Name,
			}

			pubSecret, err := r.retrieveSecret(ctxTimeout, verifySecret)
			if err != nil {
				return soci.VerificationResultFailed, err
			}

			signatureVerified := soci.VerificationResultFailed
			for k, data := range pubSecret.Data {
				// search for public keys in the secret
				if strings.HasSuffix(k, ".pub") {
					verifier, err := scosign.NewCosignVerifier(ctxTimeout, append(defaultCosignOciOpts, scosign.WithPublicKey(data))...)
					if err != nil {
						return soci.VerificationResultFailed, err
					}

					result, err := verifier.Verify(ctxTimeout, ref)
					if err != nil || result == soci.VerificationResultFailed {
						continue
					}

					if result == soci.VerificationResultSuccess {
						signatureVerified = result
						break
					}
				}
			}

			if signatureVerified == soci.VerificationResultFailed {
				return soci.VerificationResultFailed, fmt.Errorf("no matching signatures were found for '%s'", ref)
			}

			return soci.VerificationResultSuccess, nil
		}

		// if no secret is provided, try keyless verification
		ctrl.LoggerFrom(ctx).Info("no secret reference is provided, trying to verify the image using keyless method")

		var identities []cosign.Identity
		for _, match := range obj.Spec.Verify.MatchOIDCIdentity {
			identities = append(identities, cosign.Identity{
				IssuerRegExp:  match.Issuer,
				SubjectRegExp: match.Subject,
			})
		}
		defaultCosignOciOpts = append(defaultCosignOciOpts, scosign.WithIdentities(identities))

		verifier, err := scosign.NewCosignVerifier(ctxTimeout, defaultCosignOciOpts...)
		if err != nil {
			return soci.VerificationResultFailed, err
		}

		result, err := verifier.Verify(ctxTimeout, ref)
		if err != nil {
			return soci.VerificationResultFailed, err
		}

		if result == soci.VerificationResultFailed {
			return soci.VerificationResultFailed, fmt.Errorf("no matching signatures were found for '%s'", ref)
		}

		return soci.VerificationResultSuccess, nil

	case "notation":
		// get the public keys from the given secret
		secretRef := obj.Spec.Verify.SecretRef

		if secretRef == nil {
			return soci.VerificationResultFailed, fmt.Errorf("verification secret cannot be empty: '%s'", ref)
		}

		verifySecret := types.NamespacedName{
			Namespace: obj.Namespace,
			Name:      secretRef.Name,
		}

		pubSecret, err := r.retrieveSecret(ctxTimeout, verifySecret)
		if err != nil {
			return soci.VerificationResultFailed, err
		}

		data, ok := pubSecret.Data[notation.DefaultTrustPolicyKey]
		if !ok {
			return soci.VerificationResultFailed, fmt.Errorf("'%s' not found in secret '%s'", notation.DefaultTrustPolicyKey, verifySecret.String())
		}

		var doc trustpolicy.Document

		if err := json.Unmarshal(data, &doc); err != nil {
			return soci.VerificationResultFailed, fmt.Errorf("error occurred while parsing %s: %w", notation.DefaultTrustPolicyKey, err)
		}

		var certs [][]byte

		for k, data := range pubSecret.Data {
			if strings.HasSuffix(k, ".crt") || strings.HasSuffix(k, ".pem") {
				certs = append(certs, data)
			}
		}

		if certs == nil {
			return soci.VerificationResultFailed, fmt.Errorf("no certificates found in secret '%s'", verifySecret.String())
		}

		trustPolicy := notation.CleanTrustPolicy(&doc, ctrl.LoggerFrom(ctx))
		defaultNotationOciOpts := []notation.Options{
			notation.WithTrustPolicy(trustPolicy),
			notation.WithRemoteOptions(opt...),
			notation.WithAuth(auth),
			notation.WithKeychain(keychain),
			notation.WithInsecureRegistry(obj.Spec.Insecure),
			notation.WithLogger(ctrl.LoggerFrom(ctx)),
			notation.WithRootCertificates(certs),
			notation.WithTransport(transport),
		}

		verifier, err := notation.NewNotationVerifier(defaultNotationOciOpts...)
		if err != nil {
			return soci.VerificationResultFailed, err
		}

		result, err := verifier.Verify(ctxTimeout, ref)
		if err != nil {
			return result, err
		}

		if result == soci.VerificationResultFailed {
			return soci.VerificationResultFailed, fmt.Errorf("no matching signatures were found for '%s'", ref)
		}

		return result, nil
	default:
		return soci.VerificationResultFailed, fmt.Errorf("unsupported verification provider: %s", obj.Spec.Verify.Provider)
	}
}

// retrieveSecret retrieves a secret from the specified namespace with the given secret name.
// It returns the retrieved secret and any error encountered during the retrieval process.
func (r *OCIRepositoryReconciler) retrieveSecret(ctx context.Context, verifySecret types.NamespacedName) (corev1.Secret, error) {
	var pubSecret corev1.Secret

	if err := r.Get(ctx, verifySecret, &pubSecret); err != nil {
		return corev1.Secret{}, err
	}
	return pubSecret, nil
}

// parseRepository validates and extracts the repository URL.
func (r *OCIRepositoryReconciler) parseRepository(obj *sourcev1.OCIRepository) (name.Repository, error) {
	if !strings.HasPrefix(obj.Spec.URL, sourcev1.OCIRepositoryPrefix) {
		return name.Repository{}, fmt.Errorf("URL must be in format 'oci://<domain>/<org>/<repo>'")
	}

	url := strings.TrimPrefix(obj.Spec.URL, sourcev1.OCIRepositoryPrefix)

	options := []name.Option{}
	if obj.Spec.Insecure {
		options = append(options, name.Insecure)
	}
	repo, err := name.NewRepository(url, options...)
	if err != nil {
		return name.Repository{}, err
	}

	imageName := strings.TrimPrefix(url, repo.RegistryStr())
	if s := strings.Split(imageName, ":"); len(s) > 1 {
		return name.Repository{}, fmt.Errorf("URL must not contain a tag; remove ':%s'", s[1])
	}

	return repo, nil
}

// getArtifactRef determines which tag or revision should be used and returns the OCI artifact FQN.
func (r *OCIRepositoryReconciler) getArtifactRef(obj *sourcev1.OCIRepository, options []remote.Option) (name.Reference, error) {
	repo, err := r.parseRepository(obj)
	if err != nil {
		return nil, invalidOCIURLError{err}
	}

	if obj.Spec.Reference != nil {
		if obj.Spec.Reference.Digest != "" {
			return repo.Digest(obj.Spec.Reference.Digest), nil
		}

		if obj.Spec.Reference.SemVer != "" {
			return r.getTagBySemver(repo, obj.Spec.Reference.SemVer, filterTags(obj.Spec.Reference.SemverFilter), options)
		}

		if obj.Spec.Reference.Tag != "" {
			return repo.Tag(obj.Spec.Reference.Tag), nil
		}
	}

	return repo.Tag(name.DefaultTag), nil
}

// getTagBySemver call the remote container registry, fetches all the tags from the repository,
// and returns the latest tag according to the semver expression.
func (r *OCIRepositoryReconciler) getTagBySemver(repo name.Repository, exp string, filter filterFunc, options []remote.Option) (name.Reference, error) {
	tags, err := remote.List(repo, options...)
	if err != nil {
		return nil, err
	}

	validTags, err := filter(tags)
	if err != nil {
		return nil, err
	}

	constraint, err := semver.NewConstraint(exp)
	if err != nil {
		return nil, fmt.Errorf("semver '%s' parse error: %w", exp, err)
	}

	var matchingVersions []*semver.Version
	for _, t := range validTags {
		v, err := version.ParseVersion(t)
		if err != nil {
			continue
		}

		if constraint.Check(v) {
			matchingVersions = append(matchingVersions, v)
		}
	}

	if len(matchingVersions) == 0 {
		return nil, fmt.Errorf("no match found for semver: %s", exp)
	}

	sort.Sort(sort.Reverse(semver.Collection(matchingVersions)))
	return repo.Tag(matchingVersions[0].Original()), nil
}

// keychain generates the credential keychain based on the resource
// configuration. If no auth is specified a default keychain with
// anonymous access is returned
func (r *OCIRepositoryReconciler) keychain(ctx context.Context, obj *sourcev1.OCIRepository) (authn.Keychain, error) {
	var imagePullSecrets []corev1.Secret

	// lookup auth secret
	if obj.Spec.SecretRef != nil {
		var imagePullSecret corev1.Secret
		secretRef := types.NamespacedName{Namespace: obj.Namespace, Name: obj.Spec.SecretRef.Name}
		err := r.Get(ctx, secretRef, &imagePullSecret)
		if err != nil {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.AuthenticationFailedReason,
				"auth secret '%s' not found", obj.Spec.SecretRef.Name)
			return nil, fmt.Errorf("failed to get secret '%s': %w", secretRef, err)
		}
		imagePullSecrets = append(imagePullSecrets, imagePullSecret)
	}

	// lookup service account
	if obj.Spec.ServiceAccountName != "" {
		saRef := types.NamespacedName{Namespace: obj.Namespace, Name: obj.Spec.ServiceAccountName}
		saSecrets, err := secrets.PullSecretsFromServiceAccountRef(ctx, r.Client, saRef)
		if err != nil {
			return nil, err
		}
		imagePullSecrets = append(imagePullSecrets, saSecrets...)
	}

	// if no pullsecrets available return an AnonymousKeychain
	if len(imagePullSecrets) == 0 {
		return soci.Anonymous{}, nil
	}

	return k8schain.NewFromPullSecrets(ctx, imagePullSecrets)
}

// transport clones the default transport from remote and when a certSecretRef is specified,
// the returned transport will include the TLS client and/or CA certificates.
// If the insecure flag is set, the transport will skip the verification of the server's certificate.
// Additionally, if a proxy is specified, transport will use it.
func (r *OCIRepositoryReconciler) transport(ctx context.Context, obj *sourcev1.OCIRepository, proxyURL *url.URL) (*http.Transport, error) {
	transport := remote.DefaultTransport.(*http.Transport).Clone()

	tlsConfig, err := r.getTLSConfig(ctx, obj)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}

	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return transport, nil
}

// getTLSConfig gets the TLS configuration for the transport based on the
// specified secret reference in the OCIRepository object, or the insecure flag.
func (r *OCIRepositoryReconciler) getTLSConfig(ctx context.Context, obj *sourcev1.OCIRepository) (*cryptotls.Config, error) {
	if obj.Spec.CertSecretRef == nil || obj.Spec.CertSecretRef.Name == "" {
		if obj.Spec.Insecure {
			// NOTE: This is the only place in Flux where InsecureSkipVerify is allowed.
			// This exception is made for OCIRepository to maintain backward compatibility
			// with tools like crane that require insecure connections without certificates.
			// This only applies when no CertSecretRef is provided AND insecure is explicitly set.
			// All other controllers must NOT allow InsecureSkipVerify per our security policy.
			return &cryptotls.Config{
				InsecureSkipVerify: true,
			}, nil
		}
		return nil, nil
	}

	secretName := types.NamespacedName{
		Namespace: obj.Namespace,
		Name:      obj.Spec.CertSecretRef.Name,
	}
	// NOTE: Use WithSystemCertPool to maintain backward compatibility with the existing
	// extend approach (system CAs + user CA) rather than the default replace approach (user CA only).
	// This ensures source-controller continues to work with both system and user-provided CA certificates.
	var tlsOpts = []secrets.TLSConfigOption{secrets.WithSystemCertPool()}
	return secrets.TLSConfigFromSecretRef(ctx, r.Client, secretName, tlsOpts...)
}

// reconcileStorage ensures the current state of the storage matches the
// desired and previously observed state.
//
// The garbage collection is executed based on the flag configured settings and
// may remove files that are beyond their TTL or the maximum number of files
// to survive a collection cycle.
// If the Artifact in the Status of the object disappeared from the Storage,
// it is removed from the object.
// If the object does not have an Artifact in its Status, a Reconciling
// condition is added.
// The hostname of any URL in the Status of the object are updated, to ensure
// they match the Storage server hostname of current runtime.
func (r *OCIRepositoryReconciler) reconcileStorage(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.OCIRepository, _ *meta.Artifact, _ string) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	var artifactMissing bool
	if artifact := obj.GetArtifact(); artifact != nil {
		// Determine if the advertised artifact is still in storage
		if !r.Storage.ArtifactExist(*artifact) {
			artifactMissing = true
		}

		// If the artifact is in storage, verify if the advertised digest still
		// matches the actual artifact
		if !artifactMissing {
			if err := r.Storage.VerifyArtifact(*artifact); err != nil {
				r.Eventf(obj, corev1.EventTypeWarning, "ArtifactVerificationFailed", "failed to verify integrity of artifact: %s", err.Error())

				if err = r.Storage.Remove(*artifact); err != nil {
					return sreconcile.ResultEmpty, fmt.Errorf("failed to remove artifact after digest mismatch: %w", err)
				}

				artifactMissing = true
			}
		}

		// If the artifact is missing, remove it from the object
		if artifactMissing {
			obj.Status.Artifact = nil
			obj.Status.URL = ""
		}
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		msg := "building artifact"
		if artifactMissing {
			msg += ": disappeared from storage"
		}
		rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "%s", msg)
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact archives a new Artifact to the Storage, if the current
// (Status) data on the object does not match the given.
//
// The inspection of the given data to the object is differed, ensuring any
// stale observations like v1.ArtifactOutdatedCondition are removed.
// If the given Artifact does not differ from the object's current, it returns
// early.
// On a successful archive, the Artifact in the Status of the object is set,
// and the symlink in the Storage is updated to its path.
func (r *OCIRepositoryReconciler) reconcileArtifact(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.OCIRepository, metadata *meta.Artifact, dir string) (sreconcile.Result, error) {
	// Create artifact
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj, metadata.Revision,
		fmt.Sprintf("%s.tar.gz", r.digestFromRevision(metadata.Revision)))

	// Set the ArtifactInStorageCondition if there's no drift.
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) && !ociContentConfigChanged(obj) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact for digest '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) && !ociContentConfigChanged(obj) {
		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.ArtifactUpToDateReason,
			"artifact up-to-date with remote revision: '%s'", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to stat source path: %w", err),
			sourcev1.StatOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	} else if !f.IsDir() {
		e := serror.NewGeneric(
			fmt.Errorf("source path '%s' is not a directory", dir),
			sourcev1.InvalidPathReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create artifact directory: %w", err),
			sourcev1.DirCreationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		return sreconcile.ResultEmpty, serror.NewGeneric(
			fmt.Errorf("failed to acquire lock for artifact: %w", err),
			meta.FailedReason,
		)
	}
	defer unlock()

	switch obj.GetLayerOperation() {
	case sourcev1.OCILayerCopy:
		if err = r.Storage.CopyFromPath(&artifact, filepath.Join(dir, metadata.Path)); err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("unable to copy artifact to storage: %w", err),
				sourcev1.ArchiveOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	default:
		// Load ignore rules for archiving.
		ignoreDomain := strings.Split(dir, string(filepath.Separator))
		ps, err := sourceignore.LoadIgnorePatterns(dir, ignoreDomain)
		if err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(
				fmt.Errorf("failed to load source ignore patterns from repository: %w", err),
				"SourceIgnoreError",
			)
		}
		if obj.Spec.Ignore != nil {
			ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), ignoreDomain)...)
		}

		if err := r.Storage.Archive(&artifact, dir, storage.SourceIgnoreFilter(ps, ignoreDomain)); err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("unable to archive artifact to storage: %s", err),
				sourcev1.ArchiveOperationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}

	// Record the observations on the object.
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.Artifact.Metadata = metadata.Metadata
	obj.Status.ObservedIgnore = obj.Spec.Ignore
	obj.Status.ObservedLayerSelector = obj.Spec.LayerSelector

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.SymlinkUpdateFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the deletion of the object.
// It first garbage collects all Artifacts for the object from the Storage.
// Removing the finalizer from the object if successful.
func (r *OCIRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.OCIRepository) (sreconcile.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return sreconcile.ResultEmpty, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Cleanup caches.
	r.TokenCache.DeleteEventsForObject(sourcev1.OCIRepositoryKind,
		obj.GetName(), obj.GetNamespace(), cache.OperationReconcile)

	// Stop reconciliation as the object is being deleted
	return sreconcile.ResultEmpty, nil
}

// garbageCollect performs a garbage collection for the given object.
//
// It removes all but the current Artifact from the Storage, unless the
// deletion timestamp on the object is set. Which will result in the
// removal of all Artifacts for the objects.
func (r *OCIRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.OCIRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				"GarbageCollectionFailed",
			)
		} else if deleted != "" {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		delFiles, err := r.Storage.GarbageCollect(ctx, *obj.GetArtifact(), time.Second*5)
		if err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection of artifacts failed: %w", err),
				"GarbageCollectionFailed",
			)
		}
		if len(delFiles) > 0 {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected %d artifacts", len(delFiles))
			return nil
		}
	}
	return nil
}

// eventLogf records events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *OCIRepositoryReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}

// notify emits notification related to the reconciliation.
func (r *OCIRepositoryReconciler) notify(ctx context.Context, oldObj, newObj *sourcev1.OCIRepository, res sreconcile.Result, resErr error) {
	// Notify successful reconciliation for new artifact and recovery from any
	// failure.
	if resErr == nil && res == sreconcile.ResultSuccess && newObj.Status.Artifact != nil {
		annotations := map[string]string{
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaRevisionKey): newObj.Status.Artifact.Revision,
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaDigestKey):   newObj.Status.Artifact.Digest,
		}

		message := fmt.Sprintf("stored artifact with revision '%s' from '%s'", newObj.Status.Artifact.Revision, newObj.Spec.URL)

		// enrich message with upstream annotations if found
		if info := newObj.GetArtifact().Metadata; info != nil {
			var source, revision string
			if val, ok := info[oci.SourceAnnotation]; ok {
				source = val
			}
			if val, ok := info[oci.RevisionAnnotation]; ok {
				revision = val
			}
			if source != "" && revision != "" {
				message = fmt.Sprintf("%s, origin source '%s', origin revision '%s'", message, source, revision)
			}
		}

		// Notify on new artifact and failure recovery.
		if !oldObj.GetArtifact().HasDigest(newObj.GetArtifact().Digest) {
			r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
				"NewArtifact", message)
			ctrl.LoggerFrom(ctx).Info(message)
		} else {
			if sreconcile.FailureRecovery(oldObj, newObj, ociRepositoryFailConditions) {
				r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
					meta.SucceededReason, message)
				ctrl.LoggerFrom(ctx).Info(message)
			}
		}
	}
}

// makeRemoteOptions returns a remoteOptions struct with the authentication and transport options set.
// The returned struct can be used to interact with a remote registry using go-containerregistry based libraries.
func makeRemoteOptions(ctxTimeout context.Context, transport http.RoundTripper,
	keychain authn.Keychain, auth authn.Authenticator) remoteOptions {

	authOption := remote.WithAuthFromKeychain(keychain)
	if auth != nil {
		// auth take precedence over keychain here as we expect the caller to set
		// the auth only if it is required.
		authOption = remote.WithAuth(auth)
	}
	return remoteOptions{
		remote.WithContext(ctxTimeout),
		remote.WithUserAgent(oci.UserAgent),
		remote.WithTransport(transport),
		authOption,
	}
}

// remoteOptions contains the options to interact with a remote registry.
// It can be used to pass options to go-containerregistry based libraries.
type remoteOptions []remote.Option

// ociContentConfigChanged evaluates the current spec with the observations
// of the artifact in the status to determine if artifact content configuration
// has changed and requires rebuilding the artifact.
func ociContentConfigChanged(obj *sourcev1.OCIRepository) bool {
	if !ptr.Equal(obj.Spec.Ignore, obj.Status.ObservedIgnore) {
		return true
	}

	if !layerSelectorEqual(obj.Spec.LayerSelector, obj.Status.ObservedLayerSelector) {
		return true
	}

	return false
}

// Returns true if both arguments are nil or both arguments
// dereference to the same value.
// Based on k8s.io/utils/pointer/pointer.go pointer value equality.
func layerSelectorEqual(a, b *sourcev1.OCILayerSelector) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
}

func filterTags(filter string) filterFunc {
	return func(tags []string) ([]string, error) {
		if filter == "" {
			return tags, nil
		}

		match, err := regexp.Compile(filter)
		if err != nil {
			return nil, err
		}

		validTags := []string{}
		for _, tag := range tags {
			if match.MatchString(tag) {
				validTags = append(validTags, tag)
			}
		}
		return validTags, nil
	}
}
