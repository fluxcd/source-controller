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
	"encoding/base64"
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
	"k8s.io/client-go/tools/record"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/helm/chart"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	"github.com/fluxcd/source-controller/internal/oci"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
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

	helmchart := &helmv1.HelmChart{}
	helmchart.Name = "test-helmchart"
	helmchart.Namespace = namespaceName
	helmchart.Spec = helmv1.HelmChartSpec{
		Interval: metav1.Duration{Duration: interval},
		Chart:    "foo",
		SourceRef: helmv1.LocalHelmChartSourceReference{
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
		beforeFunc func(repository *helmv1.HelmRepository)
		assertFunc func(g *WithT, obj *helmv1.HelmChart, repository *helmv1.HelmRepository)
	}{
		{
			name: "Reconciles chart build",
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
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
			beforeFunc: func(repository *helmv1.HelmRepository) {
				repository.Spec.URL = "://unsupported" // Invalid URL
			},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, _ *helmv1.HelmRepository) {
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
			beforeFunc: func(repository *helmv1.HelmRepository) {
				repository.Spec.URL = strings.Replace(repository.Spec.URL, "http", "oci", 1)
			},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, _ *helmv1.HelmRepository) {
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

			repository := helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
					Namespace:    ns.Name,
				},
				Spec: helmv1.HelmRepositorySpec{
					URL: server.URL(),
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(&repository)
			}

			g.Expect(testEnv.CreateAndWait(ctx, &repository)).To(Succeed())

			obj := helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-reconcile-",
					Namespace:    ns.Name,
				},
				Spec: helmv1.HelmChartSpec{
					Chart:   chartName,
					Version: chartVersion,
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Kind: helmv1.HelmRepositoryKind,
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
		beforeFunc       func(obj *helmv1.HelmChart, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *helmv1.HelmChart, storage *Storage) error {
				revisions := []string{"a", "b", "c", "d"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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
			beforeFunc: func(obj *helmv1.HelmChart, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *helmv1.HelmChart, storage *Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *helmv1.HelmChart, storage *Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *helmv1.HelmChart, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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
					WithStatusSubresource(&helmv1.HelmChart{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmChart{
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

	storage, err := NewStorage(tmpDir, "example.com", retentionTTL, retentionRecords)
	g.Expect(err).ToNot(HaveOccurred())

	gitArtifact := &sourcev1.Artifact{
		Revision: "mock-ref/abcdefg12345678",
		Path:     "mock.tgz",
	}
	g.Expect(storage.Archive(gitArtifact, "testdata/charts", nil)).To(Succeed())

	tests := []struct {
		name       string
		source     sourcev1.Source
		beforeFunc func(obj *helmv1.HelmChart)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, build chart.Build, obj helmv1.HelmChart)
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "some-path",
					Revision: "some-rev",
				}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "unavailable",
					Kind: sourcev1.GitRepositoryKind,
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("gitrepositories.source.toolkit.fluxcd.io \"unavailable\" not found")},
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "SourceUnavailable", "failed to get source: gitrepositories.source.toolkit.fluxcd.io \"unavailable\" not found"),
					*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
					*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				}))
			},
		},
		{
			name: "Stalling on unsupported source kind",
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "unavailable",
					Kind: "Unsupported",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("unsupported source kind 'Unsupported'")},
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Spec.ValuesFiles = []string{"invalid.yaml"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("values files merge error: no values file found at path")},
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Spec.SourceRef = helmv1.LocalHelmChartSourceReference{
					Name: "gitrepository",
					Kind: sourcev1.GitRepositoryKind,
				}
				obj.Status.ObservedSourceArtifactRevision = "foo"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want: sreconcile.ResultRequeue,
			assertFunc: func(g *WithT, build chart.Build, obj helmv1.HelmChart) {
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
				WithStatusSubresource(&helmv1.HelmChart{})

			if tt.source != nil {
				clientBuilder.WithRuntimeObjects(tt.source)
			}

			r := &HelmChartReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       storage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "chart",
					Namespace:    "default",
					Generation:   1,
				},
				Spec: helmv1.HelmChartSpec{},
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
		beforeFunc func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, obj *helmv1.HelmChart, build chart.Build)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name: "Reconciles chart build",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = "helmchart"
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *helmv1.HelmChart, build chart.Build) {
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
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *helmv1.HelmChart, build chart.Build) {
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
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion
				obj.Status.Artifact = &sourcev1.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(chartVersion))
				g.Expect(build.Path).To(Equal(filepath.Join(serverFactory.Root(), obj.Status.Artifact.Path)))
				g.Expect(build.Path).To(BeARegularFile())
			},
		},
		{
			name: "Sets Generation as VersionMetadata with values files",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = chartName
				obj.Generation = 3
				obj.Spec.ValuesFiles = []string{"values.yaml", "override.yaml"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(chartName))
				g.Expect(build.Version).To(Equal(higherChartVersion + "+3"))
				g.Expect(build.Path).ToNot(BeEmpty())
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Forces build on generation change",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Generation = 3
				obj.Spec.Chart = chartName
				obj.Spec.Version = chartVersion

				obj.Status.ObservedGeneration = 2
				obj.Status.Artifact = &sourcev1.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
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
			beforeFunc: func(_ *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				repository.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "invalid",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("failed to get authentication secret '/invalid'")},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get authentication secret '/invalid'"),
				}))
			},
		},
		{
			name: "Stalling on invalid client options",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				repository.Spec.URL = "file://unsupported" // Unsupported protocol
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("scheme \"file\" not supported")},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "failed to construct Helm client"),
				}))
			},
		},
		{
			name: "Stalling on invalid repository URL",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				repository.Spec.URL = "://unsupported" // Invalid URL
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("missing protocol scheme")},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "invalid Helm repository URL"),
				}))
			},
		},
		{
			name: "BuildError on temporary build error",
			beforeFunc: func(obj *helmv1.HelmChart, _ *helmv1.HelmRepository) {
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
				WithStatusSubresource(&helmv1.HelmChart{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret.DeepCopy())
			}

			storage, err := newTestStorage(server)
			g.Expect(err).ToNot(HaveOccurred())

			r := &HelmChartReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Getters:       testGetters,
				Storage:       storage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			repository := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: helmv1.HelmRepositorySpec{
					URL:     server.URL(),
					Timeout: &metav1.Duration{Duration: timeout},
				},
				Status: helmv1.HelmRepositoryStatus{
					Artifact: &sourcev1.Artifact{
						Path: "index.yaml",
					},
				},
			}
			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: helmv1.HelmChartSpec{},
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

	storage, err := NewStorage(tmpDir, "example.com", retentionTTL, retentionRecords)
	g.Expect(err).ToNot(HaveOccurred())

	cachedArtifact := &sourcev1.Artifact{
		Revision: "0.1.0",
		Path:     metadata.Name + "-" + metadata.Version + ".tgz",
	}
	g.Expect(storage.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	tests := []struct {
		name       string
		secret     *corev1.Secret
		beforeFunc func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, obj *helmv1.HelmChart, build chart.Build)
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
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *helmv1.HelmChart, build chart.Build) {
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
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				repository.Spec.SecretRef = &meta.LocalObjectReference{Name: "auth"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, _ *helmv1.HelmChart, build chart.Build) {
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
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Status.Artifact = &sourcev1.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).To(Equal(storage.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
			},
		},
		{
			name: "Forces build on generation change",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				obj.Generation = 3
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version

				obj.Status.ObservedGeneration = 2
				obj.Status.Artifact = &sourcev1.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Name).To(Equal(metadata.Name))
				g.Expect(build.Version).To(Equal(metadata.Version))
				g.Expect(build.Path).ToNot(Equal(storage.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Event on unsuccessful secret retrieval",
			beforeFunc: func(_ *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				repository.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "invalid",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Generic{Err: errors.New("failed to get authentication secret '/invalid'")},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get authentication secret '/invalid'"),
				}))
			},
		},
		{
			name: "Stalling on invalid client options",
			beforeFunc: func(obj *helmv1.HelmChart, repository *helmv1.HelmRepository) {
				repository.Spec.URL = "https://unsupported" // Unsupported protocol
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("failed to construct Helm client: invalid OCI registry URL: https://unsupported")},
			assertFunc: func(g *WithT, obj *helmv1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "failed to construct Helm client"),
				}))
			},
		},
		{
			name: "BuildError on temporary build error",
			beforeFunc: func(obj *helmv1.HelmChart, _ *helmv1.HelmRepository) {
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
				WithStatusSubresource(&helmv1.HelmChart{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret.DeepCopy())
			}

			r := &HelmChartReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				Storage:                 storage,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			repository := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: helmv1.HelmRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/testrepo", testRegistryServer.registryHost),
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: helmv1.GenericOCIProvider,
					Type:     helmv1.HelmRepositoryTypeOCI,
				},
			}
			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: helmv1.HelmChartSpec{},
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

func TestHelmChartReconciler_buildFromTarballArtifact(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir, "example.com", retentionTTL, retentionRecords)
	g.Expect(err).ToNot(HaveOccurred())

	chartsArtifact := &sourcev1.Artifact{
		Revision: "mock-ref/abcdefg12345678",
		Path:     "mock.tgz",
	}
	g.Expect(storage.Archive(chartsArtifact, "testdata/charts", nil)).To(Succeed())
	yamlArtifact := &sourcev1.Artifact{
		Revision: "9876abcd",
		Path:     "values.yaml",
	}
	g.Expect(storage.CopyFromPath(yamlArtifact, "testdata/charts/helmchart/values.yaml")).To(Succeed())
	cachedArtifact := &sourcev1.Artifact{
		Revision: "0.1.0",
		Path:     "cached.tgz",
	}
	g.Expect(storage.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

	tests := []struct {
		name       string
		source     sourcev1.Artifact
		beforeFunc func(obj *helmv1.HelmChart)
		want       sreconcile.Result
		wantErr    error
		assertFunc func(g *WithT, build chart.Build)
		cleanFunc  func(g *WithT, build *chart.Build)
	}{
		{
			name:   "Resolves chart dependencies and builds",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *helmv1.HelmChart) {
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart"
				obj.Spec.SourceRef.Kind = sourcev1.GitRepositoryKind
				obj.Spec.ReconcileStrategy = helmv1.ReconcileStrategyRevision
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
			beforeFunc: func(obj *helmv1.HelmChart) {
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
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:   "Chart from storage cache",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Status.Artifact = cachedArtifact.DeepCopy()
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).To(Equal(storage.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
			},
		},
		{
			name:   "Generation change forces rebuild",
			source: *chartsArtifact.DeepCopy(),
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Generation = 2
				obj.Spec.Chart = "testdata/charts/helmchart-0.1.0.tgz"
				obj.Status.Artifact = cachedArtifact.DeepCopy()
				obj.Status.ObservedGeneration = 1
			},
			want: sreconcile.ResultSuccess,
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Name).To(Equal("helmchart"))
				g.Expect(build.Version).To(Equal("0.1.0"))
				g.Expect(build.Path).ToNot(Equal(storage.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name:    "Empty source artifact",
			source:  sourcev1.Artifact{},
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
					WithStatusSubresource(&helmv1.HelmChart{}).
					Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Storage:                 storage,
				Getters:                 testGetters,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "artifact",
					Namespace: "default",
				},
				Spec: helmv1.HelmChartSpec{},
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
		beforeFunc       func(obj *helmv1.HelmChart)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
		afterFunc        func(t *WithT, obj *helmv1.HelmChart)
	}{
		{
			name:  "Incomplete build requeues and does not update status",
			build: &chart.Build{},
			beforeFunc: func(obj *helmv1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: sreconcile.ResultRequeue,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "Foo", ""),
			},
		},
		{
			name:  "Copying artifact to storage from build makes ArtifactInStorage=True",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
			beforeFunc: func(obj *helmv1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, helmv1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name: "Up-to-date chart build does not persist artifact to storage",
			build: &chart.Build{
				Name:    "helmchart",
				Version: "0.1.0",
				Path:    filepath.Join(testStorage.BasePath, "testdata/charts/helmchart-0.1.0.tgz"),
			},
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path: "testdata/charts/helmchart-0.1.0.tgz",
				}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *helmv1.HelmChart) {
				t.Expect(obj.Status.Artifact.Path).To(Equal("testdata/charts/helmchart-0.1.0.tgz"))
				t.Expect(obj.Status.ObservedChartName).To(BeEmpty())
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.ObservedChartName = "helmchart"
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "0.1.0",
					Path:     "testdata/charts/helmchart-0.1.0.tgz",
				}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *helmv1.HelmChart) {
				t.Expect(obj.Status.Artifact.Path).To(Equal("testdata/charts/helmchart-0.1.0.tgz"))
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, helmv1.ChartPackageSucceededReason, "packaged 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Removes ArtifactOutdatedCondition after creating new artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
			beforeFunc: func(obj *helmv1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, helmv1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Creates latest symlink to the created artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
			afterFunc: func(t *WithT, obj *helmv1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())

				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "latest.tar.gz")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, helmv1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&helmv1.HelmChart{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
					Generation:   1,
				},
				Status: helmv1.HelmChartStatus{},
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
		&helmv1.HelmRepository{
			TypeMeta: metav1.TypeMeta{
				Kind:       helmv1.HelmRepositoryKind,
				APIVersion: helmv1.GroupVersion.String(),
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
		&helmv1.Bucket{
			TypeMeta: metav1.TypeMeta{
				Kind:       helmv1.BucketKind,
				APIVersion: helmv1.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bucket",
				Namespace: "foo",
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithStatusSubresource(&helmv1.HelmChart{}).
		WithObjects(mocks...)

	r := &HelmChartReconciler{
		Client:       clientBuilder.Build(),
		patchOptions: getPatchOptions(helmChartReadyCondition.Owned, "sc"),
	}

	tests := []struct {
		name    string
		obj     *helmv1.HelmChart
		want    sourcev1.Source
		wantErr bool
	}{
		{
			name: "Get HelmRepository source for reference",
			obj: &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[0].GetNamespace(),
				},
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Name: mocks[0].GetName(),
						Kind: mocks[0].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[0].(sourcev1.Source),
		},
		{
			name: "Get GitRepository source for reference",
			obj: &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[1].GetNamespace(),
				},
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Name: mocks[1].GetName(),
						Kind: mocks[1].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[1].(sourcev1.Source),
		},
		{
			name: "Get Bucket source for reference",
			obj: &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[2].GetNamespace(),
				},
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Name: mocks[2].GetName(),
						Kind: mocks[2].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			want: mocks[2].(sourcev1.Source),
		},
		{
			name: "Error on client error",
			obj: &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mocks[2].GetNamespace(),
				},
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Name: mocks[1].GetName(),
						Kind: mocks[2].GetObjectKind().GroupVersionKind().Kind,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error on unsupported source kind",
			obj: &helmv1.HelmChart{
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
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

			g.Expect(got).To(Equal(tt.want))
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

	obj := &helmv1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: helmv1.HelmChartStatus{},
	}

	artifact := testStorage.NewArtifactFor(helmv1.HelmChartKind, obj.GetObjectMeta(), "revision", "foo.txt")
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
		return func(_ context.Context, _ *patch.SerialPatcher, _ *helmv1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
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
				func(_ context.Context, _ *patch.SerialPatcher, obj *helmv1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
					return sreconcile.ResultSuccess, nil
				},
				func(_ context.Context, _ *patch.SerialPatcher, obj *helmv1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
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
					WithStatusSubresource(&helmv1.HelmChart{}).
					Build(),
				patchOptions: getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}
			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Status: helmv1.HelmChartStatus{
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

func mockChartBuild(name, version, path string) *chart.Build {
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
		Name:    name,
		Version: version,
		Path:    copyP,
	}
}

func TestHelmChartReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *helmv1.HelmChart)
		assertConditions []metav1.Condition
	}{
		{
			name: "positive conditions only",
			beforeFunc: func(obj *helmv1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *helmv1.HelmChart) {
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
		},
		{
			name: "mixed positive and negative conditions",
			beforeFunc: func(obj *helmv1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &helmv1.HelmChart{
				TypeMeta: metav1.TypeMeta{
					Kind:       helmv1.HelmChartKind,
					APIVersion: helmv1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "helmchart",
					Namespace: "foo",
				},
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithObjects(obj).
				WithStatusSubresource(&helmv1.HelmChart{})

			c := clientBuilder.Build()

			serialPatcher := patch.NewSerialPatcher(obj, c)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			recResult := sreconcile.ResultSuccess
			var retErr error

			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), serialPatcher)
			summarizeOpts := []summarize.Option{
				summarize.WithConditions(helmChartReadyCondition),
				summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
				summarize.WithReconcileResult(recResult),
				summarize.WithReconcileError(retErr),
				summarize.WithIgnoreNotFound(),
				summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
					RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
				}),
				summarize.WithPatchFieldOwner("source-controller"),
			}
			_, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

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
		oldObjBeforeFunc func(obj *helmv1.HelmChart)
		newObjBeforeFunc func(obj *helmv1.HelmChart)
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
			newObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal ChartPackageSucceeded packaged",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmChart) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &helmv1.HelmChart{}
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, "Unknown", "unknown build error: failed to construct Helm client's TLS config: cannot append certificate into certificate pool: invalid CA certificate"),
			},
		},
		{
			name: "HTTPS With CA cert",
			want: sreconcile.ResultSuccess,
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
				WithStatusSubresource(&helmv1.HelmChart{})

			workspaceDir := t.TempDir()

			if tt.insecure {
				tt.registryOpts.disableDNSMocking = true
			}
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

			repo := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: helmv1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Type:     helmv1.HelmRepositoryTypeOCI,
					Provider: helmv1.GenericOCIProvider,
					URL:      fmt.Sprintf("oci://%s/testrepo", server.registryHost),
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

			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: helmv1.HelmChartSpec{
					Chart:   metadata.Name,
					Version: metadata.Version,
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Kind: helmv1.HelmRepositoryKind,
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
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_reconcileSourceFromOCI_verifySignature(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{
		disableDNSMocking: true,
	})
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

	storage, err := NewStorage(tmpDir, "example.com", retentionTTL, retentionRecords)
	g.Expect(err).ToNot(HaveOccurred())

	cachedArtifact := &sourcev1.Artifact{
		Revision: "0.1.0",
		Path:     metadata.Name + "-" + metadata.Version + ".tgz",
	}
	g.Expect(storage.CopyFromPath(cachedArtifact, "testdata/charts/helmchart-0.1.0.tgz")).To(Succeed())

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
		beforeFunc       func(obj *helmv1.HelmChart)
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		assertConditions []metav1.Condition
		cleanFunc        func(g *WithT, build *chart.Build)
	}{
		{
			name: "unsigned charts should not pass verification",
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &helmv1.OCIRepositoryVerification{
					Provider:  "cosign",
					SecretRef: &meta.LocalObjectReference{Name: "cosign-key"},
				}
			},
			want:       sreconcile.ResultEmpty,
			wantErr:    true,
			wantErrMsg: "chart verification error: failed to verify <url>: no matching signatures",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no matching signatures"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no matching signatures"),
			},
		},
		{
			name: "unsigned charts should not pass keyless verification",
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &helmv1.OCIRepositoryVerification{
					Provider: "cosign",
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ChartVerificationError", "chart verification error: failed to verify <url>: no matching signatures"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "chart verification error: failed to verify <url>: no matching signatures"),
			},
		},
		{
			name:       "signed charts should pass verification",
			shouldSign: true,
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = &helmv1.OCIRepositoryVerification{
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
			beforeFunc: func(obj *helmv1.HelmChart) {
				obj.Spec.Chart = metadata.Name
				obj.Spec.Version = metadata.Version
				obj.Spec.Verify = nil
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Status.Artifact = &sourcev1.Artifact{Path: metadata.Name + "-" + metadata.Version + ".tgz"}
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

			repository := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
				},
				Spec: helmv1.HelmRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/testrepo", server.registryHost),
					Timeout:  &metav1.Duration{Duration: timeout},
					Provider: helmv1.GenericOCIProvider,
					Type:     helmv1.HelmRepositoryTypeOCI,
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
				Storage:                 storage,
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmChartReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmchart-",
				},
				Spec: helmv1.HelmChartSpec{
					SourceRef: helmv1.LocalHelmChartSourceReference{
						Kind: helmv1.HelmRepositoryKind,
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
					Registry:         coptions.RegistryOptions{Keychain: oci.Anonymous{}, AllowInsecure: true},
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
