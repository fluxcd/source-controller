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

package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/pkg/artifact/config"
	"github.com/fluxcd/pkg/artifact/digest"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	nr "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	. "github.com/onsi/gomega"
	coptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	hchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	oras "oras.land/oras-go/v2/registry/remote"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kstatus "github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	serror "github.com/werf/nelm-source-controller/internal/error"
	"github.com/werf/nelm-source-controller/internal/helm/chart"
	"github.com/werf/nelm-source-controller/internal/helm/chart/secureloader"
	"github.com/werf/nelm-source-controller/internal/helm/registry"
	"github.com/werf/nelm-source-controller/internal/oci"
	snotation "github.com/werf/nelm-source-controller/internal/oci/notation"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
)

func TestHelmChartReconciler_deleteBeforeFinalizer(t *testing.T) {
	g := NewWithT(t)

	namespaceName := "helmchart-" + randStringRunes(5)
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}
	g.Expect(k8sClient.Create(ctx, namespace)).ToNot(HaveOccurred())
	t.Cleanup(func() {
		g.Expect(k8sClient.Delete(ctx, namespace)).NotTo(HaveOccurred())
	})

	helmchart := &sourcev1.HelmChart{}
	helmchart.Name = "test-helmchart"
	helmchart.Namespace = namespaceName
	helmchart.Spec = sourcev1.HelmChartSpec{
		Interval: metav1.Duration{Duration: interval},
		Chart:    "foo",
		SourceRef: sourcev1.LocalHelmChartSourceReference{
			Kind: "HelmRepository",
			Name: "bar",
		},
	}
	// Add a test finalizer to prevent the object from getting deleted.
	helmchart.SetFinalizers([]string{"test-finalizer"})
	g.Expect(k8sClient.Create(ctx, helmchart)).NotTo(HaveOccurred())
	// Add deletion timestamp by deleting the object.
	g.Expect(k8sClient.Delete(ctx, helmchart)).NotTo(HaveOccurred())

	r := &HelmChartReconciler{
		Client:        k8sClient,
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}
	// NOTE: Only a real API server responds with an error in this scenario.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(helmchart)})
	g.Expect(err).NotTo(HaveOccurred())
}

func TestHelmChartReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	const (
		chartName    = "helmchart"
		chartVersion = "0.2.0"
		chartPath    = "testdata/charts/helmchart"
	)

	serverFactory, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(serverFactory.Root())

	g.Expect(serverFactory.PackageChartWithVersion(chartPath, chartVersion)).To(Succeed())
	g.Expect(serverFactory.GenerateIndex()).To(Succeed())

	tests := []struct {
		name       string
		beforeFunc func(repository *sourcev1.HelmRepository)
		assertFunc func(g *WithT, obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository)
	}{
		{
			name: "Reconciles chart build",
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				origObj := obj.DeepCopy()

				key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

				// Wait for finalizer to be set
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return false
					}
					return len(obj.Finalizers) > 0
				}, timeout).Should(BeTrue())

				// Wait for HelmChart to be Ready
				waitForSourceReadyWithArtifact(ctx, g, obj)

				// Check if the object status is valid.
				condns := &conditionscheck.Conditions{NegativePolarity: helmChartReadyCondition.NegativePolarity}
				checker := conditionscheck.NewChecker(testEnv.Client, condns)
				checker.WithT(g).CheckErr(ctx, obj)

				// kstatus client conformance check.
				u, err := patch.ToUnstructured(obj)
				g.Expect(err).ToNot(HaveOccurred())
				res, err := kstatus.Compute(u)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(res.Status).To(Equal(kstatus.CurrentStatus))

				// Patch the object with reconcile request annotation.
				patchHelper, err := patch.NewHelper(obj, testEnv.Client)
				g.Expect(err).ToNot(HaveOccurred())
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "now",
				}
				obj.SetAnnotations(annotations)
				g.Expect(patchHelper.Patch(ctx, obj)).ToNot(HaveOccurred())
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return false
					}
					return obj.Status.LastHandledReconcileAt == "now"
				}, timeout).Should(BeTrue())

				// Check if the cache contains the index.
				repoKey := client.ObjectKey{Name: repository.Name, Namespace: repository.Namespace}
				err = testEnv.Get(ctx, repoKey, repository)
				g.Expect(err).ToNot(HaveOccurred())
				_, found := testCache.Get(repository.GetArtifact().Path)
				g.Expect(found).To(BeTrue())

				g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

				// Wait for HelmChart to be deleted
				waitForSourceDeletion(ctx, g, obj)

				// Check if a suspended object gets deleted.
				// NOTE: Since the object is already created when received in
				// this assertFunc, reset the ResourceVersion from the object
				// before recreating it to avoid API server error.
				obj = origObj.DeepCopy()
				obj.ResourceVersion = ""
				testSuspendedObjectDeleteWithArtifact(ctx, g, obj)
			},
		},
		{
			name: "Stalling on invalid repository URL",
			beforeFunc: func(repository *sourcev1.HelmRepository) {
				repository.Spec.URL = "https://unsupported/foo://" // Invalid URL
			},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}
				// Wait for HelmChart to be FetchFailed == true
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return false
					}
					if !conditions.IsTrue(obj, sourcev1.FetchFailedCondition) {
						return false
					}
					// observedGeneration is -1 because we have no successful reconciliation
					return obj.Status.ObservedGeneration == -1
				}, timeout).Should(BeTrue())

				// Check if the object status is valid.
				condns := &conditionscheck.Conditions{NegativePolarity: helmChartReadyCondition.NegativePolarity}
				checker := conditionscheck.NewChecker(testEnv.Client, condns)
				checker.WithT(g).CheckErr(ctx, obj)

				g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

				// Wait for HelmChart to be deleted
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return apierrors.IsNotFound(err)
					}
					return false
				}, timeout).Should(BeTrue())
			},
		},
		{
			name: "Stalling on invalid oci repository URL",
			beforeFunc: func(repository *sourcev1.HelmRepository) {
				repository.Spec.URL = strings.Replace(repository.Spec.URL, "http", "oci", 1)
			},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}
				// Wait for HelmChart to be Ready
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return false
					}
					if !conditions.IsTrue(obj, sourcev1.FetchFailedCondition) {
						return false
					}
					// observedGeneration is -1 because we have no successful reconciliation
					return obj.Status.ObservedGeneration == -1
				}, timeout).Should(BeTrue())

				// Check if the object status is valid.
				condns := &conditionscheck.Conditions{NegativePolarity: helmChartReadyCondition.NegativePolarity}
				checker := conditionscheck.NewChecker(testEnv.Client, condns)
				checker.WithT(g).CheckErr(ctx, obj)

				g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

				// Wait for HelmChart to be deleted
				g.Eventually(func() bool {
					if err := testEnv.Get(ctx, key, obj); err != nil {
						return apierrors.IsNotFound(err)
					}
					return false
				}, timeout).Should(BeTrue())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server := testserver.NewHTTPServer(serverFactory.Root())
			server.Start()
			defer server.Stop()

			ns, err := testEnv.CreateNamespace(ctx, "helmchart")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			repository := sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL: server.URL(),
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(&repository)
			}

			g.Expect(testEnv.CreateAndWait(ctx, &repository)).To(Succeed())
			defer func() { g.Expect(testEnv.Delete(ctx, &repository)).To(Succeed()) }()

			obj := sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-reconcile-",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.HelmChartSpec{
					Chart:   chartName,
					Version: chartVersion,
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repository.Name,
					},
				},
			}
			g.Expect(testEnv.Create(ctx, &obj)).To(Succeed())

			if tt.assertFunc != nil {
				tt.assertFunc(g, &obj, &repository)
			}
		})
	}
}

func TestHelmChartReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmChart, storage *storage.Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *meta.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *storage.Storage) error {
				revisions := []string{"a", "b", "c", "d"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &meta.Artifact{
						Path:     fmt.Sprintf("/reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}
					if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0o640); err != nil {
						return err
					}
					if n != len(revisions)-1 {
						time.Sleep(time.Second * 1)
					}
				}
				storage.SetArtifactURL(obj.Status.Artifact)
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			assertArtifact: &meta.Artifact{
				Path:     "/reconcile-storage/d.txt",
				Revision: "d",
				Digest:   "sha256:18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
				URL:      testStorage.Hostname + "/reconcile-storage/d.txt",
				Size:     int64p(int64(len("d"))),
			},
			assertPaths: []string{
				"/reconcile-storage/d.txt",
				"/reconcile-storage/c.txt",
				"!/reconcile-storage/b.txt",
				"!/reconcile-storage/a.txt",
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "build artifact first time",
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact"),
			},
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/reconcile-storage/invalid.txt",
					Revision: "d",
				}
				storage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices empty artifact digest",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *storage.Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = ""

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/empty-digest.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices artifact digest mismatch",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *storage.Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = "sha256:6c329d5322473f904e2f908a51c12efa0ca8aa4201dd84f2c9d203a6ab3e9023"

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/digest-mismatch.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/reconcile-storage/hostname.txt",
					Revision: "f",
					Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
					URL:      "http://outdated.com/reconcile-storage/hostname.txt",
				}
				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0o640); err != nil {
					return err
				}
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"/reconcile-storage/hostname.txt",
			},
			assertArtifact: &meta.Artifact{
				Path:     "/reconcile-storage/hostname.txt",
				Revision: "f",
				Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
				URL:      testStorage.Hostname + "/reconcile-storage/hostname.txt",
				Size:     int64p(int64(len("file"))),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			defer func() {
				g.Expect(os.RemoveAll(filepath.Join(testStorage.BasePath, "/reconcile-storage"))).To(Succeed())
			}()

			r := &HelmChartReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.HelmChart{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   1,
				},
			}
			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileStorage(context.TODO(), sp, obj, nil)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(obj.Status.Artifact).To(MatchArtifact(tt.assertArtifact))
			if tt.assertArtifact != nil && tt.assertArtifact.URL != "" {
				g.Expect(obj.Status.Artifact.URL).To(Equal(tt.assertArtifact.URL))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			for _, p := range tt.assertPaths {
				absoluteP := filepath.Join(testStorage.BasePath, p)
				if !strings.HasPrefix(p, "!") {
					g.Expect(absoluteP).To(BeAnExistingFile())
					continue
				}
				g.Expect(absoluteP).NotTo(BeAnExistingFile())
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestHelmChartReconciler_reconcileSource(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()

	opts := &config.Options{
		StoragePath:              tmpDir,
		StorageAddress:           "example.com",
		StorageAdvAddress:        "example.com",
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	gitArtifact := &meta.Artifact{
		Revision: "mock-ref/abcdefg12345678",
		Path:     "mock.tgz",
	}
	g.Expect(st.Archive(gitArtifact, "testdata/charts", nil)).To(Succeed())

	tests := []struct {
		name       string
		source     sourcev1.Source
		beforeFunc func(obj *sourcev1.HelmChart)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, build chart.Build, obj sourcev1.HelmChart)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name: "Observes Artifact revision and build result",
			source: &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gitrepository",
					Namespace: "default",
				},
				Status: sourcev1.GitRepositoryStatus{
					Artifact: gitArtifact,
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeTrue())
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).To(BeARegularFile())

				g.Expect(obj.Status.ObservedSourceArtifactRevision).To(Equal(gitArtifact.Revision))
				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
					*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				}))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Existing artifact makes AritfactOutdated=True",
			source: &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gitrepository",
					Namespace: "default",
				},
				Status: sourcev1.GitRepositoryStatus{
					Artifact: gitArtifact,
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Status.Artifact = &meta.Artifact{
					Path:     "some-path",
					Revision: "some-rev",
				}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeTrue())
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).To(BeARegularFile())

				g.Expect(obj.Status.ObservedSourceArtifactRevision).To(Equal(gitArtifact.Revision))
				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewChart", "pulled 'helmchart' chart with version '0.1.0'"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
					*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				}))
			},
		},
		{
			name: "Error on unavailable source",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "unavailable",
					Kind: sourcev1.GitRepositoryKind,
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("gitrepositories.source.werf.io \"unavailable\" not found")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "SourceUnavailable", "failed to get source: gitrepositories.source.werf.io \"unavailable\" not found"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
					*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				}))
			},
		},
		{
			name: "Stalling on unsupported source kind",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "unavailable",
					Kind: "Unsupported",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("unsupported source kind 'Unsupported'")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "SourceUnavailable", "failed to get source: unsupported source kind"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
					*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
				}))
			},
		},
		{
			name: "Stalling on persistent build error",
			source: &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gitrepository",
					Namespace: "default",
				},
				Status: sourcev1.GitRepositoryStatus{
					Artifact: gitArtifact,
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Spec.ValuesFiles = []string{"invalid.yaml"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("values files merge error: no values file found at path")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ValuesFilesError", "values files merge error: no values file found at path"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
					*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
				}))
			},
		},
		{
			name: "ResultRequeue when source artifact is unavailable",
			source: &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gitrepository",
					Namespace: "default",
				},
				Status: sourcev1.GitRepositoryStatus{},
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Status.ObservedSourceArtifactRevision = "foo"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want: sreconcile.ResultRequeue,
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.ObservedSourceArtifactRevision).To(Equal("foo"))
				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "NoSourceArtifact", "no artifact available"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
					*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
				}))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.HelmChart{})

			if tt.source != nil {
				clientBuilder.WithRuntimeObjects(tt.source)
			}

			r := &HelmChartReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       st,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "chart",
					Namespace:    "default",
					Generation:   1,
				},
				Spec: sourcev1.HelmChartSpec{},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(&obj)
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}

			g.Expect(r.Client.Create(context.TODO(), &obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), &obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(&obj, r.Client)

			got, err := r.reconcileSource(context.TODO(), sp, &obj, &b)

			g.Expect(err != nil).To(Equal(tt.wantErr != nil))
			if tt.wantErr != nil {
				g.Expect(reflect.TypeOf(err).String()).To(Equal(reflect.TypeOf(tt.wantErr).String()))
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr.Error()))
			}
			g.Expect(got).To(Equal(tt.want))

			if tt.assertFunc != nil {
				tt.assertFunc(g, b, obj)
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, &obj)
		})
	}
}

func TestHelmChartReconciler_buildFromHelmRepository(t *testing.T) {
	g := NewWithT(t)

	const (
		chartName          = "helmchart"
		chartVersion       = "0.2.0"
		higherChartVersion = "0.3.0"
		chartPath          = "testdata/charts/helmchart"
	)

	serverFactory, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(serverFactory.Root())

	for _, ver := range []string{chartVersion, higherChartVersion} {
		g.Expect(serverFactory.PackageChartWithVersion(chartPath, ver)).To(Succeed())
	}
	g.Expect(serverFactory.GenerateIndex()).To(Succeed())

	type options struct {
		username string
		password string
	}

	tests := []struct {
		name       string
		server     options
		secret     *corev1.Secret
		beforeFunc func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, obj *sourcev1.HelmChart, build chart.Build)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name: "Reconciles chart build",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = "helmchart"
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(higherChartVersion))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Reconciles chart build with repository credentials",
			server: options{
				username: "foo",
				password: "bar",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth",
				},
				Data: map[string][]byte{
					"username": []byte("foo"),
					"password": []byte("bar"),
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Uses artifact as build cache",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				obj.Status.Artifact = &meta.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion))
				g.Expect(build.Path).To(Equal(filepath.Join(serverFactory.Root(), obj.Status.Artifact.Path)))
				g.Expect(build.Path).To(BeARegularFile())
			},
		},
		{
			name: "Uses artifact as build cache with observedValuesFiles",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				obj.Status.Artifact = &meta.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
				obj.Status.ObservedValuesFiles = []string{"values.yaml", "override.yaml"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion))
				g.Expect(build.Path).To(Equal(filepath.Join(serverFactory.Root(), obj.Status.Artifact.Path)))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(Equal([]string{"values.yaml", "override.yaml"}))
			},
		},
		{
			name: "Sets Generation as VersionMetadata with values files",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Generation = 3
				obj.Spec.ValuesFiles = []string{"values.yaml", "override.yaml"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(higherChartVersion + "+3"))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(Equal([]string{"values.yaml", "override.yaml"}))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Missing values files are an error",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.ValuesFiles = []string{"missing.yaml"}
			},
			wantErr: &chart.BuildError{Err: errors.New("values files merge error: failed to merge chart values: no values file found at path 'missing.yaml'")},
		},
		{
			name: "All missing values files ignored",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				obj.Spec.ValuesFiles = []string{"missing.yaml"}
				obj.Spec.IgnoreMissingValuesFiles = true
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion + "+0"))
				g.Expect(build.ValuesFiles).To(BeEmpty())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Partial missing values files ignored",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				obj.Spec.ValuesFiles = []string{"values.yaml", "override.yaml", "invalid.yaml"}
				obj.Spec.IgnoreMissingValuesFiles = true
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion + "+0"))
				g.Expect(build.ValuesFiles).To(Equal([]string{"values.yaml", "override.yaml"}))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Forces build on generation change",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Generation = 3
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion

				obj.Status.ObservedGeneration = 2
				obj.Status.Artifact = &meta.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion))
				g.Expect(build.Path).ToNot(Equal(filepath.Join(serverFactory.Root(), obj.Status.Artifact.Path)))
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Event on unsuccessful secret retrieval",
			beforeFunc: func(_ *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "invalid",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("failed to get authentication secret '/invalid': secrets \"invalid\" not found")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get authentication secret '/invalid': secrets \"invalid\" not found"),
				}))
			},
		},
		{
			name: "Stalling on invalid client options",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.URL = "file://unsupported" // Unsupported protocol
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("scheme \"file\" not supported")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "failed to construct Helm client"),
				}))
			},
		},
		{
			name: "Stalling on invalid repository URL",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.URL = "://unsupported" // Invalid URL
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("missing protocol scheme")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "invalid Helm repository URL"),
				}))
			},
		},
		{
			name: "BuildError on temporary build error",
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Chart = "invalid"
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &chart.BuildError{Err: errors.New("failed to get chart version for remote reference")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server := testserver.NewHTTPServer(serverFactory.Root())
			server.Start()
			defer server.Stop()

			if len(tt.server.username+tt.server.password) > 0 {
				server.WithMiddleware(func(handler http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						u, p, ok := r.BasicAuth()
						if !ok || u != tt.server.username || p != tt.server.password {
							w.WriteHeader(401)
							return
						}
						handler.ServeHTTP(w, r)
					})
				})
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithStatusSubresource(&sourcev1.HelmChart{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret.DeepCopy())
			}

			testStorage, err := newTestStorage(server)
			g.Expect(err).ToNot(HaveOccurred())

			r := &HelmChartReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Getters:       testGetters,
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:     server.URL(),
					Timeout: &metav1.Duration{Duration: timeout},
				},
				Status: sourcev1.HelmRepositoryStatus{
					Artifact: &meta.Artifact{
						Path: "index.yaml",
					},
				},
			}
			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmChartSpec{},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, repository)
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}
			got, err := r.buildFromHelmRepository(context.TODO(), obj, repository, &b)

			g.Expect(err != nil).To(Equal(tt.wantErr != nil))
			if tt.wantErr != nil {
				g.Expect(reflect.TypeOf(err).String()).To(Equal(reflect.TypeOf(tt.wantErr).String()))
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr.Error()))
			}
			g.Expect(got).To(Equal(tt.want))

			if tt.assertFunc != nil {
				tt.assertFunc(g, obj, b)
			}
		})
	}
}

func TestHelmChartReconciler_buildFromOCIHelmRepository(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()

	const (
		chartPath = "testdata/charts/helmchart-0.1.0.tgz"
	)

	// Load a test chart
	chartData, err := os.ReadFile(chartPath)
	g.Expect(err).NotTo(HaveOccurred())

	// Upload the test chart
	metadata, err := loadTestChartToOCI(chartData, testRegistryServer, "", "", "")
	g.Expect(err).NotTo(HaveOccurred())

	opts := &config.Options{
		StoragePath:              tmpDir,
		StorageAddress:           "example.com",
		StorageAdvAddress:        "example.com",
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	cachedArtifact := &meta.Artifact{
		Revision: "0.1.0",
		Path:     metadata.Name + "-" + metadata.Version + ".tgz",
	}
	g.Expect(st.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	tests := []struct {
		name       string
		secret     *corev1.Secret
		beforeFunc func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, obj *sourcev1.HelmChart, build chart.Build)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name: "Reconciles chart build with docker repository credentials",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"` +
						testRegistryServer.registryHost + `":{"` +
						`auth":"` + base64.StdEncoding.EncodeToString([]byte(testRegistryUsername+":"+testRegistryPassword)) + `"}}}`),
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Reconciles chart build with repository credentials",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth",
				},
				Data: map[string][]byte{
					"username": []byte(testRegistryUsername),
					"password": []byte(testRegistryPassword),
				},
			},
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Uses artifact as build cache",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Status.Artifact = &meta.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).To(Equal(st.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(BeEmpty())
			},
		},
		{
			name: "Forces build on generation change",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				obj.Generation = 3
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version

				obj.Status.ObservedGeneration = 2
				obj.Status.Artifact = &meta.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).ToNot(Equal(st.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Event on unsuccessful secret retrieval",
			beforeFunc: func(_ *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "invalid",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("failed to get authentication secret '/invalid': secrets \"invalid\" not found")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get authentication secret '/invalid': secrets \"invalid\" not found"),
				}))
			},
		},
		{
			name: "Stalling on invalid client options",
			beforeFunc: func(obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.URL = "https://unsupported" // Unsupported protocol
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("failed to construct Helm client: invalid OCI registry URL: https://unsupported")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "failed to construct Helm client"),
				}))
			},
		},
		{
			name: "BuildError on temporary build error",
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Chart = "invalid"
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &chart.BuildError{Err: errors.New("failed to get chart version for remote reference")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithStatusSubresource(&sourcev1.HelmChart{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret.DeepCopy())
			}

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				Storage:                 st,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/testrepo", testRegistryServer.registryHost),
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: sourcev1.GenericOCIProvider,
					Type:     sourcev1.HelmRepositoryTypeOCI,
					Insecure: true,
				},
			}
			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmChartSpec{},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, repository)
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}
			got, err := r.buildFromHelmRepository(context.TODO(), obj, repository, &b)

			if tt.wantErr != nil {
				g.Expect(err).To(HaveOccurred())
				g.Expect(reflect.TypeOf(err).String()).To(Equal(reflect.TypeOf(tt.wantErr).String()))
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr.Error()))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(got).To(Equal(tt.want))
			}

			if tt.assertFunc != nil {
				tt.assertFunc(g, obj, b)
			}
		})
	}
}

func TestHelmChartReconciler_buildFromTarballArtifact(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()

	opts := &config.Options{
		StoragePath:              tmpDir,
		StorageAddress:           "example.com",
		StorageAdvAddress:        "example.com",
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	chartsArtifact := &meta.Artifact{
		Revision: "mock-ref/abcdefg12345678",
		Path:     "mock.tgz",
	}
	g.Expect(st.Archive(chartsArtifact, "testdata/charts", nil)).To(Succeed())
	yamlArtifact := &meta.Artifact{
		Revision: "9876abcd",
		Path:     "values.yaml",
	}
	g.Expect(st.CopyFromPath(yamlArtifact, "testdata/charts/helmchart/values.yaml")).To(Succeed())
	cachedArtifact := &meta.Artifact{
		Revision: "0.1.0",
		Path:     "cached.tgz",
	}
	g.Expect(st.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	tests := []struct {
		name       string
		source     meta.Artifact
		beforeFunc func(obj *sourcev1.HelmChart)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, build chart.Build)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name:   "Resolves chart dependencies and builds",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchartwithdeps"
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchartwithdeps"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.ResolvedDependencies).To(Equal(4))
				g.Expect(build.Path).To(BeARegularFile())
				chart, err := secureloader.LoadFile(build.Path)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(chart.Metadata.Name).To(Equal("helmchartwithdeps"))
				g.Expect(chart.Metadata.Version).To(Equal("0.1.0"))
				g.Expect(chart.Dependencies()).To(HaveLen(4))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:   "ReconcileStrategyRevision sets VersionMetadata",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart"
				obj.Spec.SourceRef.Kind = sourcev1.GitRepositoryKind
				obj.Spec.ReconcileStrategy = sourcev1.ReconcileStrategyRevision
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0+abcdefg12345"))
				g.Expect(build.ResolvedDependencies).To(Equal(0))
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:   "ValuesFiles sets Generation as VersionMetadata",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Generation = 3
				obj.Spec.Chart = "testdata/charts/helmchart"
				obj.Spec.SourceRef.Kind = sourcev1.GitRepositoryKind
				obj.Spec.ValuesFiles = []string{
					filepath.Join(obj.Spec.Chart, "values.yaml"),
					filepath.Join(obj.Spec.Chart, "override.yaml"),
				}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0+3"))
				g.Expect(build.ResolvedDependencies).To(Equal(0))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(Equal([]string{
					"testdata/charts/helmchart/values.yaml",
					"testdata/charts/helmchart/override.yaml",
				}))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:   "Chart from storage cache",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Status.Artifact = cachedArtifact.DeepCopy()
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).To(Equal(st.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(BeEmpty())
			},
		},
		{
			name:   "Chart from storage cache with ObservedValuesFiles",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Status.Artifact = cachedArtifact.DeepCopy()
				obj.Status.ObservedValuesFiles = []string{"values.yaml", "override.yaml"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).To(Equal(st.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(Equal([]string{"values.yaml", "override.yaml"}))
			},
		},
		{
			name:   "Generation change forces rebuild",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Generation = 2
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Status.Artifact = cachedArtifact.DeepCopy()
				obj.Status.ObservedGeneration = 1
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).ToNot(Equal(st.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
				g.Expect(build.ValuesFiles).To(BeEmpty())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:    "Empty source artifact",
			source:  meta.Artifact{},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("no such file or directory")},
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())
			},
		},
		{
			name:    "Invalid artifact type",
			source:  *yamlArtifact,
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("artifact untar error: requires gzip-compressed body")},
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.Scheme()).
					WithStatusSubresource(&sourcev1.HelmChart{}).
					Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Storage:                 st,
				Getters:                 testGetters,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "artifact",
					Namespace: "default",
				},
				Spec: sourcev1.HelmChartSpec{},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}

			got, err := r.buildFromTarballArtifact(context.TODO(), obj, tt.source, &b)
			if err != nil {
				t.Log(err)
			}
			g.Expect(err != nil).To(Equal(tt.wantErr != nil))
			if tt.wantErr != nil {
				g.Expect(reflect.TypeOf(err).String()).To(Equal(reflect.TypeOf(tt.wantErr).String()))
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr.Error()))
			}
			g.Expect(got).To(Equal(tt.want))

			if tt.assertFunc != nil {
				tt.assertFunc(g, b)
			}
		})
	}
}

func TestHelmChartReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		build            *chart.Build
		beforeFunc       func(obj *sourcev1.HelmChart)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
		afterFunc        func(t *WithT, obj *sourcev1.HelmChart)
	}{
		{
			name:  "Incomplete build requeues and does not update status",
			build: &chart.Build{},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: sreconcile.ResultRequeue,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "Foo", ""),
			},
		},
		{
			name:  "Copying artifact to storage from build makes ArtifactInStorage=True",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz", nil),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
				t.Expect(obj.Status.ObservedValuesFiles).To(BeNil())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name: "Up-to-date chart build does not persist artifact to storage",
			build: &chart.Build{
				Name:    "helmchart",
				Version: "0.1.0",
				Path:    filepath.Join(testStorage.BasePath, "testdata/charts/helmchart-0.1.0.tgz"),
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{
					Path: "testdata/charts/helmchart-0.1.0.tgz",
				}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.Status.Artifact.Path).To(Equal("testdata/charts/helmchart-0.1.0.tgz"))
				t.Expect(obj.Status.ObservedChartName).To(BeEmpty())
				t.Expect(obj.Status.ObservedValuesFiles).To(BeNil())
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
		},
		{
			name: "Restores conditions in case artifact matches current chart build",
			build: &chart.Build{
				Name:     "helmchart",
				Version:  "0.1.0",
				Path:     filepath.Join(testStorage.BasePath, "testdata/charts/helmchart-0.1.0.tgz"),
				Packaged: true,
			},
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.ObservedChartName = "helmchart"
				obj.Status.Artifact = &meta.Artifact{
					Revision: "0.1.0",
					Path:     "testdata/charts/helmchart-0.1.0.tgz",
				}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.Status.Artifact.Path).To(Equal("testdata/charts/helmchart-0.1.0.tgz"))
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPackageSucceededReason, "packaged 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Removes ArtifactOutdatedCondition after creating new artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz", nil),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
				t.Expect(obj.Status.ObservedValuesFiles).To(BeNil())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Creates latest symlink to the created artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz", nil),
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())

				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "latest.tar.gz")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Updates ObservedValuesFiles after creating new artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz", []string{"values.yaml", "override.yaml"}),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
				t.Expect(obj.Status.ObservedValuesFiles).To(BeNil())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Updates ObservedValuesFiles with IgnoreMissingValuesFiles after creating new artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz", []string{"values.yaml", "override.yaml"}),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
				obj.Spec.ValuesFiles = []string{"values.yaml", "missing.yaml", "override.yaml"}
				obj.Spec.IgnoreMissingValuesFiles = true
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
				t.Expect(obj.Status.ObservedValuesFiles).To(Equal([]string{"values.yaml", "override.yaml"}))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.HelmChart{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
					Generation:   1,
				},
				Status: sourcev1.HelmChartStatus{},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileArtifact(ctx, sp, obj, tt.build)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestHelmChartReconciler_getSource(t *testing.T) {
	mocks := []client.Object{
		&sourcev1.HelmRepository{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.HelmRepositoryKind,
				APIVersion: sourcev1.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "helmrepository",
				Namespace: "foo",
			},
		},
		&sourcev1.GitRepository{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.GitRepositoryKind,
				APIVersion: sourcev1.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gitrepository",
				Namespace: "foo",
			},
		},
		&sourcev1.Bucket{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.BucketKind,
				APIVersion: sourcev1.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bucket",
				Namespace: "foo",
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithStatusSubresource(&sourcev1.HelmChart{}).
		WithObjects(mocks...)

	r := &HelmChartReconciler{
		Client:       clientBuilder.Build(),
		patchOptions: getPatchOptions(helmChartReadyCondition.Owned, "sc"),
	}

	tests := []struct {
		name    string
		obj     *sourcev1.HelmChart
		want    sourcev1.Source
		wantErr bool
	}{
		{
			name: "Get HelmRepository source for reference",
			obj: &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[0].GetNamespace(),
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Name: mocks[0].GetName(),
						Kind: mocks[0].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[0].(sourcev1.Source),
		},
		{
			name: "Get GitRepository source for reference",
			obj: &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[1].GetNamespace(),
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Name: mocks[1].GetName(),
						Kind: mocks[1].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[1].(sourcev1.Source),
		},
		{
			name: "Get Bucket source for reference",
			obj: &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[2].GetNamespace(),
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Name: mocks[2].GetName(),
						Kind: mocks[2].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[2].(sourcev1.Source),
		},
		{
			name: "Error on client error",
			obj: &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[2].GetNamespace(),
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Name: mocks[1].GetName(),
						Kind: mocks[2].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error on unsupported source kind",
			obj: &sourcev1.HelmChart{
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Name: "unsupported",
						Kind: "Unsupported",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := r.getSource(context.TODO(), tt.obj)

			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				g.Expect(got).To(BeNil())
				return
			}

			// TODO(stefan): Remove this workaround when the controller-runtime fake client restores TypeMeta
			// https://github.com/kubernetes-sigs/controller-runtime/issues/3302
			unstructuredGot, err := runtime.DefaultUnstructuredConverter.ToUnstructured(got)
			g.Expect(err).ToNot(HaveOccurred())
			gotName, _, err := unstructured.NestedFieldCopy(unstructuredGot, "metadata", "name")
			g.Expect(err).ToNot(HaveOccurred())
			unstructuredWant, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tt.want)
			g.Expect(err).ToNot(HaveOccurred())
			wantName, _, err := unstructured.NestedFieldCopy(unstructuredWant, "metadata", "name")
			g.Expect(err).ToNot(HaveOccurred())

			g.Expect(gotName).To(Equal(wantName))
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestHelmChartReconciler_reconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &HelmChartReconciler{
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
	}

	obj := &sourcev1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: sourcev1.HelmChartStatus{},
	}

	artifact := testStorage.NewArtifactFor(sourcev1.HelmChartKind, obj.GetObjectMeta(), "revision", "foo.txt")
	obj.Status.Artifact = &artifact

	got, err := r.reconcileDelete(ctx, obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(sreconcile.ResultEmpty))
	g.Expect(controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer)).To(BeFalse())
	g.Expect(obj.Status.Artifact).To(BeNil())
}

func TestHelmChartReconciler_reconcileSubRecs(t *testing.T) {
	// Helper to build simple helmChartReconcileFunc with result and error.
	buildReconcileFuncs := func(r sreconcile.Result, e error) helmChartReconcileFunc {
		return func(_ context.Context, _ *patch.SerialPatcher, _ *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
			return r, e
		}
	}

	tests := []struct {
		name               string
		generation         int64
		observedGeneration int64
		reconcileFuncs     []helmChartReconcileFunc
		wantResult         sreconcile.Result
		wantErr            bool
		assertConditions   []metav1.Condition
	}{
		{
			name: "successful reconciliations",
			reconcileFuncs: []helmChartReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "reconciliation in progress"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress"),
			},
		},
		{
			name:               "successful reconciliation with generation difference",
			generation:         3,
			observedGeneration: 2,
			reconcileFuncs: []helmChartReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "processing object: new generation 2 -> 3"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "processing object: new generation 2 -> 3"),
			},
		},
		{
			name: "failed reconciliation",
			reconcileFuncs: []helmChartReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "reconciliation in progress"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress"),
			},
		},
		{
			name: "multiple object status conditions mutations",
			reconcileFuncs: []helmChartReconcileFunc{
				func(_ context.Context, _ *patch.SerialPatcher, obj *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
					return sreconcile.ResultSuccess, nil
				},
				func(_ context.Context, _ *patch.SerialPatcher, obj *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, meta.ReconcilingCondition, "Progressing", "creating artifact")
					return sreconcile.ResultSuccess, nil
				},
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "creating artifact"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress"),
			},
		},
		{
			name: "subrecs with one result=Requeue, no error",
			reconcileFuncs: []helmChartReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultRequeue,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "reconciliation in progress"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress"),
			},
		},
		{
			name: "subrecs with error before result=Requeue",
			reconcileFuncs: []helmChartReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "reconciliation in progress"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.HelmChart{}).
					Build(),
				patchOptions: getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}
			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Status: sourcev1.HelmChartStatus{
					ObservedGeneration: tt.observedGeneration,
				},
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcile(context.TODO(), sp, obj, tt.reconcileFuncs)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.wantResult))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func mockChartBuild(name, version, path string, valuesFiles []string) *chart.Build {
	var copyP string
	if path != "" {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			ff, err := os.CreateTemp("", "chart-mock-*.tgz")
			if err == nil {
				defer ff.Close()
				if _, err = io.Copy(ff, f); err == nil {
					copyP = ff.Name()
				}
			}
		}
	}
	return &chart.Build{
		Name:        name,
		Version:     version,
		Path:        copyP,
		ValuesFiles: valuesFiles,
	}
}

func TestHelmChartReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmChart)
		assertConditions []metav1.Condition
		wantErr          bool
	}{
		{
			name: "positive conditions only",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
				conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory")
				conditions.MarkTrue(obj, sourcev1.BuildFailedCondition, "ChartPackageError", "some error")
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartPackageError", "some error"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error"),
			},
			wantErr: true,
		},
		{
			name: "mixed positive and negative conditions",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.HelmChart{
				TypeMeta: metav1.TypeMeta{
					Kind:       sourcev1.HelmChartKind,
					APIVersion: sourcev1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "helmchart",
					Namespace: "foo",
				},
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithObjects(obj).
				WithStatusSubresource(&sourcev1.HelmChart{})

			c := clientBuilder.Build()

			serialPatcher := patch.NewSerialPatcher(obj, c)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), serialPatcher)
			summarizeOpts := []summarize.Option{
				summarize.WithConditions(helmChartReadyCondition),
				summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
				summarize.WithReconcileResult(sreconcile.ResultSuccess),
				summarize.WithIgnoreNotFound(),
				summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
					RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
				}),
				summarize.WithPatchFieldOwner("source-controller"),
			}
			_, err := summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)
			g.Expect(err != nil).To(Equal(tt.wantErr))

			key := client.ObjectKeyFromObject(obj)
			g.Expect(c.Get(ctx, key, obj)).ToNot(HaveOccurred())
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_notify(t *testing.T) {
	tests := []struct {
		name             string
		res              sreconcile.Result
		resErr           error
		oldObjBeforeFunc func(obj *sourcev1.HelmChart)
		newObjBeforeFunc func(obj *sourcev1.HelmChart)
		wantEvent        string
	}{
		{
			name:   "error - no event",
			res:    sreconcile.ResultEmpty,
			resErr: errors.New("some error"),
		},
		{
			name:   "new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.HelmChart{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &HelmChartReconciler{
				EventRecorder: recorder,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}
			build := &chart.Build{
				Name:     "foo",
				Version:  "1.0.0",
				Path:     "some/path",
				Packaged: true,
			}
			reconciler.notify(ctx, oldObj, newObj, build, tt.res, tt.resErr)

			select {
			case x, ok := <-recorder.Events:
				g.Expect(ok).To(Equal(tt.wantEvent != ""), "unexpected event received")
				if tt.wantEvent != "" {
					g.Expect(x).To(ContainSubstring(tt.wantEvent))
				}
			default:
				if tt.wantEvent != "" {
					t.Errorf("expected some event to be emitted")
				}
			}
		})
	}
}

func TestHelmChartReconciler_reconcileSourceFromOCI_authStrategy(t *testing.T) {
	const (
		chartPath = "testdata/charts/helmchart-0.1.0.tgz"
	)

	type secretOptions struct {
		username string
		password string
	}

	tests := []struct {
		name             string
		url              string
		registryOpts     registryOptions
		secretOpts       secretOptions
		secret           *corev1.Secret
		certSecret       *corev1.Secret
		insecure         bool
		provider         string
		providerImg      string
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name:     "HTTP without basic auth",
			want:     sreconcile.ResultSuccess,
			insecure: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:     "HTTP with basic auth secret",
			want:     sreconcile.ResultSuccess,
			insecure: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:     "HTTP registry - basic auth with invalid secret",
			want:     sreconcile.ResultEmpty,
			wantErr:  true,
			insecure: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: "wrong-pass",
				password: "wrong-pass",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "unknown build error: failed to login to OCI registry"),
			},
		},
		{
			name:        "with contextual login provider",
			wantErr:     true,
			insecure:    true,
			provider:    "aws",
			providerImg: "oci://123456789000.dkr.ecr.us-east-2.amazonaws.com/test",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "unknown build error: failed to get credential from"),
			},
		},
		{
			name: "with contextual login provider and secretRef",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			provider: "azure",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:    "HTTPS With invalid CA cert",
			wantErr: true,
			registryOpts: registryOptions{
				withTLS:            true,
				withClientCertAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "certs-secretref",
				},
				Data: map[string][]byte{
					"ca.crt": []byte("invalid caFile"),
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "unknown build error: failed to construct Helm client's TLS config: failed to parse CA certificate"),
			},
		},
		{
			name: "HTTPS With CA cert only",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTLS: true,
			},
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "certs-secretref",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"ca.crt": tlsCA,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name: "HTTPS With CA cert and client cert auth",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTLS:            true,
				withClientCertAuth: true,
			},
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "certs-secretref",
				},
				Data: map[string][]byte{
					"ca.crt":  tlsCA,
					"tls.crt": clientPublicKey,
					"tls.key": clientPrivateKey,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.HelmChart{})

			workspaceDir := t.TempDir()

			server, err := setupRegistryServer(ctx, workspaceDir, tt.registryOpts)
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			// Load a test chart
			chartData, err := os.ReadFile(chartPath)
			g.Expect(err).ToNot(HaveOccurred())

			// Upload the test chart
			metadata, err := loadTestChartToOCI(chartData, server, "testdata/certs/client.pem", "testdata/certs/client-key.pem", "testdata/certs/ca.pem")
			g.Expect(err).ToNot(HaveOccurred())

			repo := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Type:     sourcev1.HelmRepositoryTypeOCI,
					Provider: sourcev1.GenericOCIProvider,
					URL:      fmt.Sprintf("oci://%s/testrepo", server.registryHost),
					Insecure: tt.insecure,
				},
			}

			if tt.provider != "" {
				repo.Spec.Provider = tt.provider
			}
			// If a provider specific image is provided, overwrite existing URL
			// set earlier. It'll fail, but it's necessary to set them because
			// the login check expects the URLs to be of certain pattern.
			if tt.providerImg != "" {
				repo.Spec.URL = tt.providerImg
			}

			if tt.secretOpts.username != "" && tt.secretOpts.password != "" {
				tt.secret.Data[".dockerconfigjson"] = []byte(fmt.Sprintf(`{"auths": {%q: {"username": %q, "password": %q}}}`,
					server.registryHost, tt.secretOpts.username, tt.secretOpts.password))
			}

			if tt.secret != nil {
				repo.Spec.SecretRef = &meta.LocalObjectReference{
					Name: tt.secret.Name,
				}
				clientBuilder.WithObjects(tt.secret)
			}

			if tt.certSecret != nil {
				repo.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.certSecret.Name,
				}
				clientBuilder.WithObjects(tt.certSecret)
			}

			clientBuilder.WithObjects(repo)

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: sourcev1.HelmChartSpec{
					Chart:   metadata.Name,
					Version: metadata.Version,
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repo.Name,
					},
					Interval: metav1.Duration{Duration: interval},
				},
			}

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			var b chart.Build
			defer func() {
				if _, err := os.Stat(b.Path); !os.IsNotExist(err) {
					err := os.Remove(b.Path)
					g.Expect(err).NotTo(HaveOccurred())
				}
			}()

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<helmchart>", metadata.Name)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<version>", metadata.Version)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(ctx, sp, obj, &b)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(got).To(Equal(tt.want))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartRepository_reconcileSource_verifyOCISourceSignature_keyless(t *testing.T) {
	tests := []struct {
		name             string
		version          string
		want             sreconcile.Result
		wantErr          bool
		beforeFunc       func(obj *sourcev1.HelmChart)
		assertConditions []metav1.Condition
		revision         string
	}{
		{
			name:    "signed image with no identity matching specified should pass verification",
			version: "6.5.1",
			want:    sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			revision: "6.5.1@sha256:af589b918022cd8d85a4543312d28170c2e894ccab8484050ff4bdefdde30b4e",
		},
		{
			name:    "signed image with correct subject and issuer should pass verification",
			version: "6.5.1",
			want:    sreconcile.ResultSuccess,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{

						Subject: "^https://github.com/stefanprodan/podinfo.*$",
						Issuer:  "^https://token.actions.githubusercontent.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			revision: "6.5.1@sha256:af589b918022cd8d85a4543312d28170c2e894ccab8484050ff4bdefdde30b4e",
		},
		{
			name:    "signed image with incorrect and correct identity matchers should pass verification",
			version: "6.5.1",
			want:    sreconcile.ResultSuccess,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{
						Subject: "intruder",
						Issuer:  "^https://honeypot.com$",
					},
					{

						Subject: "^https://github.com/stefanprodan/podinfo.*$",
						Issuer:  "^https://token.actions.githubusercontent.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			revision: "6.5.1@sha256:af589b918022cd8d85a4543312d28170c2e894ccab8484050ff4bdefdde30b4e",
		},
		{
			name:    "signed image with incorrect subject and issuer should not pass verification",
			version: "6.5.1",
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{
						Subject: "intruder",
						Issuer:  "^https://honeypot.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no matching signatures: none of the expected identities matched what was in the certificate"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no matching signatures"),
			},
			revision: "6.5.1@sha256:af589b918022cd8d85a4543312d28170c2e894ccab8484050ff4bdefdde30b4e",
		},
		{
			name:    "unsigned image should not pass verification",
			version: "6.1.0",
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no signatures found"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no signatures found"),
			},
			revision: "6.1.0@sha256:642383f56ccb529e3f658d40312d01b58d9bc6caeef653da43e58d1afe88982a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder()

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      "oci://ghcr.io/stefanprodan/charts",
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: sourcev1.GenericOCIProvider,
					Type:     sourcev1.HelmRepositoryTypeOCI,
				},
			}
			clientBuilder.WithObjects(repository)

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				Storage:                 testStorage,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmchart-",
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repository.Name,
					},
					Version: tt.version,
					Chart:   "podinfo",
					Verify: &sourcev1.OCIRepositoryVerification{
						Provider: "cosign",
					},
				},
			}
			chartUrl := fmt.Sprintf("%s/%s:%s", repository.Spec.URL, obj.Spec.Chart, obj.Spec.Version)

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<name>", obj.Spec.Chart)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<version>", obj.Spec.Version)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", chartUrl)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "cosign")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			var b chart.Build
			got, err := r.reconcileSource(ctx, sp, obj, &b)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_reconcileSourceFromOCI_verifySignatureNotation(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		server.Close()
	})

	const (
		chartPath = "testdata/charts/helmchart-0.1.0.tgz"
	)

	// Load a test chart
	chartData, err := os.ReadFile(chartPath)
	g.Expect(err).ToNot(HaveOccurred())

	// Upload the test chart
	metadata, err := loadTestChartToOCI(chartData, server, "", "", "")
	g.Expect(err).NotTo(HaveOccurred())

	opts := &config.Options{
		StoragePath:              tmpDir,
		StorageAddress:           server.registryHost,
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	cachedArtifact := &meta.Artifact{
		Revision: "0.1.0",
		Path:     metadata.Name + "-" + metadata.Version + ".tgz",
	}
	g.Expect(st.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	certTuple := testhelper.GetRSASelfSignedSigningCertTuple("notation self-signed certs for testing")
	certs := []*x509.Certificate{certTuple.Cert}

	sg, err := signer.New(certTuple.PrivateKey, certs)
	g.Expect(err).ToNot(HaveOccurred())

	policyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name, Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	tests := []struct {
		name             string
		shouldSign       bool
		beforeFunc       func(obj *sourcev1.HelmChart)
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		addMultipleCerts bool
		provideNoCert    bool
		provideNoPolicy  bool
		assertConditions []metav1.Condition
		cleanFunc        func(g *WithT, build *chart.Build)
	}{
		{
			name: "unsigned charts should not pass verification",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "notation",
					SecretRef: &meta.LocalObjectReference{Name: "notation-config"},
				}
			},
			want:       sreconcile.ResultEmpty,
			wantErr:    true,
			wantErrMsg: "chart verification error: failed to verify <url>: no signature",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no signature"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no signature"),
			},
		},
		{
			name:       "signed charts should pass verification",
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "notation",
					SecretRef: &meta.LocalObjectReference{Name: "notation-config"},
				}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:             "multiple certs should still pass verification",
			addMultipleCerts: true,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "notation",
					SecretRef: &meta.LocalObjectReference{Name: "notation-config"},
				}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "verify failed before, removed from spec, remove condition",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = nil
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Status.Artifact = &meta.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewChart", "pulled '<name>' chart with version '<version>'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "no cert provided should not pass verification",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "notation",
					SecretRef: &meta.LocalObjectReference{Name: "notation-config"},
				}
			},
			wantErr:       true,
			provideNoCert: true,
			// no namespace but the namespace name should appear before the /notation-config
			wantErrMsg: "failed to verify the signature using provider 'notation': no certificates found in secret '/notation-config'",
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "failed to verify the signature using provider 'notation': no certificates found in secret '/notation-config'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider 'notation': no certificates found in secret '/notation-config'"),
			},
		},
		{
			name: "empty string should fail verification",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "notation",
					SecretRef: &meta.LocalObjectReference{Name: "notation-config"},
				}
			},
			provideNoPolicy: true,
			wantErr:         true,
			wantErrMsg:      fmt.Sprintf("failed to verify the signature using provider 'notation': '%s' not found in secret '/notation-config'", snotation.DefaultTrustPolicyKey),
			want:            sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "failed to verify the signature using provider 'notation': '%s' not found in secret '/notation-config'", snotation.DefaultTrustPolicyKey),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider 'notation': '%s' not found in secret '/notation-config'", snotation.DefaultTrustPolicyKey),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder()

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/testrepo", server.registryHost),
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: sourcev1.GenericOCIProvider,
					Type:     sourcev1.HelmRepositoryTypeOCI,
					Insecure: true,
				},
			}

			policy, err := json.Marshal(policyDocument)
			g.Expect(err).NotTo(HaveOccurred())

			data := map[string][]byte{}

			if tt.addMultipleCerts {
				data["a.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("a not used for signing").Cert.Raw
				data["b.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("b not used for signing").Cert.Raw
				data["c.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("c not used for signing").Cert.Raw
			}

			if !tt.provideNoCert {
				data["notation.crt"] = certTuple.Cert.Raw
			}

			if !tt.provideNoPolicy {
				data["trustpolicy.json"] = policy
			}

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "notation-config",
				},
				Data: data,
			}

			caSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-trust-store",
					Generation: 1,
				},
				Data: map[string][]byte{
					"ca.crt": tlsCA,
				},
			}

			clientBuilder.WithObjects(repository, secret, caSecret)

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				Storage:                 st,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmchart-",
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repository.Name,
					},
				},
			}

			chartUrl := fmt.Sprintf("oci://%s/testrepo/%s:%s", server.registryHost, metadata.Name, metadata.Version)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			if tt.shouldSign {
				artifact := fmt.Sprintf("%s/testrepo/%s:%s", server.registryHost, metadata.Name, metadata.Version)

				remoteRepo, err := oras.NewRepository(artifact)
				g.Expect(err).ToNot(HaveOccurred())

				remoteRepo.PlainHTTP = true

				repo := nr.NewRepository(remoteRepo)

				signatureMediaType := cose.MediaTypeEnvelope

				signOptions := notation.SignOptions{
					SignerSignOptions: notation.SignerSignOptions{
						SignatureMediaType: signatureMediaType,
					},
					ArtifactReference: artifact,
				}

				_, err = notation.Sign(ctx, sg, repo, signOptions)
				g.Expect(err).ToNot(HaveOccurred())
			}

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<name>", metadata.Name)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<version>", metadata.Version)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", chartUrl)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "notation")
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(ctx, sp, obj, &b)
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", chartUrl)
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_reconcileSourceFromOCI_verifySignatureCosign(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		server.Close()
	})

	const (
		chartPath = "testdata/charts/helmchart-0.1.0.tgz"
	)

	// Load a test chart
	chartData, err := os.ReadFile(chartPath)
	g.Expect(err).ToNot(HaveOccurred())

	// Upload the test chart
	metadata, err := loadTestChartToOCI(chartData, server, "", "", "")
	g.Expect(err).NotTo(HaveOccurred())

	opts := &config.Options{
		StoragePath:              tmpDir,
		StorageAddress:           server.registryHost,
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	cachedArtifact := &meta.Artifact{
		Revision: "0.1.0",
		Path:     metadata.Name + "-" + metadata.Version + ".tgz",
	}
	g.Expect(st.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	pf := func(b bool) ([]byte, error) {
		return []byte("cosign-password"), nil
	}

	keys, err := cosign.GenerateKeyPair(pf)
	g.Expect(err).ToNot(HaveOccurred())

	err = os.WriteFile(path.Join(tmpDir, "cosign.key"), keys.PrivateBytes, 0600)
	g.Expect(err).ToNot(HaveOccurred())

	defer func() {
		err := os.Remove(path.Join(tmpDir, "cosign.key"))
		g.Expect(err).ToNot(HaveOccurred())
	}()

	tests := []struct {
		name             string
		shouldSign       bool
		beforeFunc       func(obj *sourcev1.HelmChart)
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		assertConditions []metav1.Condition
		cleanFunc        func(g *WithT, build *chart.Build)
	}{
		{
			name: "unsigned charts should not pass verification",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "cosign",
					SecretRef: &meta.LocalObjectReference{Name: "cosign-key"},
				}
			},
			want:       sreconcile.ResultEmpty,
			wantErr:    true,
			wantErrMsg: "chart verification error: failed to verify <url>: no signatures found",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no signatures found"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no signatures found"),
			},
		},
		{
			name: "unsigned charts should not pass keyless verification",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider: "cosign",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no signatures found"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no signatures found"),
			},
		},
		{
			name:       "signed charts should pass verification",
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &sourcev1.OCIRepositoryVerification{
					Provider:  "cosign",
					SecretRef: &meta.LocalObjectReference{Name: "cosign-key"},
				}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of version <version>"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "verify failed before, removed from spec, remove condition",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = nil
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Status.Artifact = &meta.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewChart", "pulled '<name>' chart with version '<version>'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: pulled '<name>' chart with version '<version>'"),
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder()

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/testrepo", server.registryHost),
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: sourcev1.GenericOCIProvider,
					Type:     sourcev1.HelmRepositoryTypeOCI,
					Insecure: true,
				},
			}

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cosign-key",
				},
				Data: map[string][]byte{
					"cosign.pub": keys.PublicBytes,
				}}

			clientBuilder.WithObjects(repository, secret)

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				Storage:                 st,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmchart-",
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repository.Name,
					},
				},
			}

			chartUrl := fmt.Sprintf("oci://%s/testrepo/%s:%s", server.registryHost, metadata.Name, metadata.Version)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			if tt.shouldSign {
				ko := coptions.KeyOpts{
					KeyRef:   path.Join(tmpDir, "cosign.key"),
					PassFunc: pf,
				}

				ro := &coptions.RootOptions{
					Timeout: timeout,
				}

				err = sign.SignCmd(ro, ko, coptions.SignOptions{
					Upload:           true,
					SkipConfirmation: true,
					TlogUpload:       false,
					Registry:         coptions.RegistryOptions{Keychain: oci.Anonymous{}, AllowHTTPRegistry: true},
				},
					[]string{fmt.Sprintf("%s/testrepo/%s:%s", server.registryHost, metadata.Name, metadata.Version)})
				g.Expect(err).ToNot(HaveOccurred())
			}

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<name>", metadata.Name)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<version>", metadata.Version)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", chartUrl)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "cosign")
			}

			var b chart.Build
			if tt.cleanFunc != nil {
				defer tt.cleanFunc(g, &b)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(ctx, sp, obj, &b)
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", chartUrl)
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

// extractChartMeta is used to extract a chart metadata from a byte array
func extractChartMeta(chartData []byte) (*hchart.Metadata, error) {
	ch, err := loader.LoadArchive(bytes.NewReader(chartData))
	if err != nil {
		return nil, err
	}
	return ch.Metadata, nil
}

func loadTestChartToOCI(chartData []byte, server *registryClientTestServer, certFile, keyFile, cafile string) (*hchart.Metadata, error) {
	// Login to the registry
	err := server.registryClient.Login(server.registryHost,
		helmreg.LoginOptBasicAuth(testRegistryUsername, testRegistryPassword),
		helmreg.LoginOptTLSClientConfig(certFile, keyFile, cafile))
	if err != nil {
		return nil, fmt.Errorf("failed to login to OCI registry: %w", err)
	}
	metadata, err := extractChartMeta(chartData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract chart metadata: %w", err)
	}

	// Upload the test chart
	ref := fmt.Sprintf("%s/testrepo/%s:%s", server.registryHost, metadata.Name, metadata.Version)
	_, err = server.registryClient.Push(chartData, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to push chart: %w", err)
	}

	return metadata, nil
}
