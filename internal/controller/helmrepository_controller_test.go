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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/cache"
	intdigest "github.com/fluxcd/source-controller/internal/digest"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
)

func TestHelmRepositoryReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	testServer, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(testServer.Root())

	g.Expect(testServer.PackageChart("testdata/charts/helmchart")).To(Succeed())
	g.Expect(testServer.GenerateIndex()).To(Succeed())

	testServer.Start()
	defer testServer.Stop()

	origObj := &helmv1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: helmv1.HelmRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      testServer.URL(),
		},
	}
	obj := origObj.DeepCopy()
	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmRepository to be Ready
	waitForSourceReadyWithArtifact(ctx, g, obj)

	// Check if the object status is valid.
	condns := &conditionscheck.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
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

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmRepository to be deleted
	waitForSourceDeletion(ctx, g, obj)

	// Check if a suspended object gets deleted.
	obj = origObj.DeepCopy()
	testSuspendedObjectDeleteWithArtifact(ctx, g, obj)
}

func TestHelmRepositoryReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *helmv1.HelmRepository, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *helmv1.HelmRepository, storage *Storage) error {
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
			beforeFunc: func(obj *helmv1.HelmRepository, storage *Storage) error {
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
			beforeFunc: func(obj *helmv1.HelmRepository, storage *Storage) error {
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
			beforeFunc: func(obj *helmv1.HelmRepository, storage *Storage) error {
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
			beforeFunc: func(obj *helmv1.HelmRepository, storage *Storage) error {
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

			r := &HelmRepositoryReconciler{
				Client:        fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme()).Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(helmRepositoryReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmRepository{
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

			var chartRepo repository.ChartRepository
			var artifact sourcev1.Artifact
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileStorage(context.TODO(), sp, obj, &artifact, &chartRepo)
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

func TestHelmRepositoryReconciler_reconcileSource(t *testing.T) {
	type options struct {
		username   string
		password   string
		publicKey  []byte
		privateKey []byte
		ca         []byte
	}

	tests := []struct {
		name             string
		protocol         string
		server           options
		url              string
		secret           *corev1.Secret
		beforeFunc       func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest)
		afterFunc        func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name:     "HTTPS with secretRef pointing to CA cert but public repo URL succeeds",
			protocol: "http",
			url:      "https://stefanprodan.github.io/podinfo",
			want:     sreconcile.ResultSuccess,
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": tlsCA,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
		},
		{
			name:     "HTTP without secretRef makes ArtifactOutdated=True",
			protocol: "http",
			want:     sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).ToNot(BeNil())
				t.Expect(artifact.Revision).ToNot(BeEmpty())
			},
		},
		{
			name:     "HTTP with Basic Auth secret makes ArtifactOutdated=True",
			protocol: "http",
			server: options{
				username: "git",
				password: "1234",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "basic-auth",
				},
				Data: map[string][]byte{
					"username": []byte("git"),
					"password": []byte("1234"),
				},
			},
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "basic-auth"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).ToNot(BeNil())
				t.Expect(artifact.Revision).ToNot(BeEmpty())
			},
		},
		{
			name:     "HTTPS with CAFile secret makes ArtifactOutdated=True",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": tlsCA,
				},
			},
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).ToNot(BeNil())
				t.Expect(artifact.Revision).ToNot(BeEmpty())
			},
		},
		{
			name:     "HTTPS with invalid CAFile secret makes FetchFailed=True and returns error",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-ca",
				},
				Data: map[string][]byte{
					"caFile": []byte("invalid"),
				},
			},
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-ca"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to create TLS client config with secret data: cannot append certificate into certificate pool: invalid caFile"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Path).To(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Invalid URL makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "")
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "first path segment in URL cannot contain colon"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Path).To(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Unsupported scheme makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "ftp://")
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "scheme \"ftp\" not supported"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Path).To(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Missing secret returns FetchFailed=True and returns error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "secrets \"non-existing\" not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Path).To(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Malformed secret returns FetchFailed=True and returns error",
			protocol: "http",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "malformed-basic-auth",
				},
				Data: map[string][]byte{
					"username": []byte("git"),
				},
			},
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "malformed-basic-auth"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "required fields 'username' and 'password"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Path).To(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Stored index with same digest and revision",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: rev.String(),
					Digest:   dig.String(),
				}

				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "foo", "bar")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).To(BeNil())

				t.Expect(&artifact).To(BeEquivalentTo(obj.Status.Artifact))
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:     "Stored index with different digest and same revision",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: rev.String(),
					Digest:   "sha256:80bb3dd67c63095d985850459834ea727603727a370079de90d221191d375a86",
				}

				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "foo", "bar")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).ToNot(BeNil())

				t.Expect(artifact.Revision).To(Equal(obj.Status.Artifact.Revision))
				t.Expect(artifact.Digest).ToNot(Equal(obj.Status.Artifact.Digest))
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:     "Stored index with different revision and digest",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "80bb3dd67c63095d985850459834ea727603727a370079de90d221191d375a86",
					Digest:   "sha256:80bb3dd67c63095d985850459834ea727603727a370079de90d221191d375a86",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) {
				t.Expect(chartRepo.Path).ToNot(BeEmpty())
				t.Expect(chartRepo.Index).ToNot(BeNil())

				t.Expect(artifact.Path).To(Not(BeEmpty()))
				t.Expect(artifact.Revision).ToNot(Equal(obj.Status.Artifact.Revision))
				t.Expect(artifact.Digest).ToNot(Equal(obj.Status.Artifact.Digest))
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:     "Existing artifact makes ArtifactOutdated=True",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, rev, dig digest.Digest) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "some-path",
					Revision: "some-rev",
				}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new index revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new index revision"),
			},
		},
	}

	for _, tt := range tests {
		obj := &helmv1.HelmRepository{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "auth-strategy-",
				Generation:   1,
			},
			Spec: helmv1.HelmRepositorySpec{
				Interval: metav1.Duration{Duration: interval},
				Timeout:  &metav1.Duration{Duration: timeout},
			},
		}

		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server, err := helmtestserver.NewTempHelmServer()
			g.Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(server.Root())

			g.Expect(server.PackageChart("testdata/charts/helmchart")).To(Succeed())
			g.Expect(server.GenerateIndex()).To(Succeed())

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

			secret := tt.secret.DeepCopy()
			switch tt.protocol {
			case "http":
				server.Start()
				defer server.Stop()
				obj.Spec.URL = server.URL()
				if tt.url != "" {
					obj.Spec.URL = tt.url
				}
			case "https":
				g.Expect(server.StartTLS(tt.server.publicKey, tt.server.privateKey, tt.server.ca, "example.com")).To(Succeed())
				defer server.Stop()
				obj.Spec.URL = server.URL()
				if tt.url != "" {
					obj.Spec.URL = tt.url
				}
			default:
				t.Fatalf("unsupported protocol %q", tt.protocol)
			}

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			// Calculate the artifact digest for valid repos configurations.
			clientOpts := []helmgetter.Option{
				helmgetter.WithURL(server.URL()),
			}
			var newChartRepo *repository.ChartRepository
			var tOpts *tls.Config
			validSecret := true
			if secret != nil {
				// Extract the client options from secret, ignoring any invalid
				// value. validSecret is used to determine if the index digest
				// should be calculated below.
				var cOpts []helmgetter.Option
				var serr error
				cOpts, serr = getter.ClientOptionsFromSecret(*secret)
				if serr != nil {
					validSecret = false
				}
				clientOpts = append(clientOpts, cOpts...)
				repoURL := server.URL()
				if tt.url != "" {
					repoURL = tt.url
				}
				tOpts, serr = getter.TLSClientConfigFromSecret(*secret, repoURL)
				if serr != nil {
					validSecret = false
				}
				newChartRepo, err = repository.NewChartRepository(obj.Spec.URL, "", testGetters, tOpts, clientOpts...)
			} else {
				newChartRepo, err = repository.NewChartRepository(obj.Spec.URL, "", testGetters, nil)
			}
			g.Expect(err).ToNot(HaveOccurred())

			// NOTE: digest will be empty in beforeFunc for invalid repo
			// configurations as the client can't get the repo.
			var rev, dig digest.Digest
			if validSecret {
				g.Expect(newChartRepo.CacheIndex()).To(Succeed())
				dig = newChartRepo.Digest(intdigest.Canonical)

				g.Expect(newChartRepo.LoadFromPath()).To(Succeed())
				rev = newChartRepo.Digest(intdigest.Canonical)
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, rev, dig)
			}

			r := &HelmRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        builder.Build(),
				Storage:       testStorage,
				Getters:       testGetters,
				patchOptions:  getPatchOptions(helmRepositoryReadyCondition.Owned, "sc"),
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			var chartRepo repository.ChartRepository
			var artifact sourcev1.Artifact
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(context.TODO(), sp, obj, &artifact, &chartRepo)
			defer os.Remove(chartRepo.Path)

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, artifact, &chartRepo)
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestHelmRepositoryReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		cache            *cache.Cache
		beforeFunc       func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository)
		afterFunc        func(t *WithT, obj *helmv1.HelmRepository, cache *cache.Cache)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archiving artifact to storage makes ArtifactInStorage=True",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'existing'"),
			},
		},
		{
			name:  "Archiving (loaded) artifact to storage adds to cache",
			cache: cache.New(10, time.Minute),
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				index.Index = &repo.IndexFile{
					APIVersion: "v1",
					Generated:  time.Now(),
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, cache *cache.Cache) {
				i, ok := cache.Get(obj.GetArtifact().Path)
				t.Expect(ok).To(BeTrue())
				t.Expect(i).To(BeAssignableToTypeOf(&repo.IndexFile{}))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'existing'"),
			},
		},
		{
			name: "Up-to-date artifact should not update status",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Status.Artifact = artifact.DeepCopy()
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, _ *cache.Cache) {
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'existing'"),
			},
		},
		{
			name: "Removes ArtifactOutdatedCondition after creating a new artifact",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'existing'"),
			},
		},
		{
			name: "Creates latest symlink to the created artifact",
			beforeFunc: func(t *WithT, obj *helmv1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *helmv1.HelmRepository, _ *cache.Cache) {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "index.yaml")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'existing'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmRepositoryReconciler{
				Client:        fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme()).Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				Cache:         tt.cache,
				TTL:           1 * time.Minute,
				patchOptions:  getPatchOptions(helmRepositoryReadyCondition.Owned, "sc"),
			}

			obj := &helmv1.HelmRepository{
				TypeMeta: metav1.TypeMeta{
					Kind: helmv1.HelmRepositoryKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
					Namespace:    "default",
				},
				Spec: helmv1.HelmRepositorySpec{
					Timeout: &metav1.Duration{Duration: timeout},
					URL:     "https://example.com/index.yaml",
				},
			}

			tmpDir := t.TempDir()

			// Create an empty cache file.
			cachePath := filepath.Join(tmpDir, "index.yaml")
			cacheFile, err := os.Create(cachePath)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cacheFile.Close()).ToNot(HaveOccurred())

			chartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", testGetters, nil)
			g.Expect(err).ToNot(HaveOccurred())
			chartRepo.Path = cachePath

			artifact := testStorage.NewArtifactFor(obj.Kind, obj, "existing", "foo.tar.gz")
			// Digest of the index file calculated by the ChartRepository.
			artifact.Digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, artifact, chartRepo)
			}
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileArtifact(context.TODO(), sp, obj, &artifact, chartRepo)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			// On error, artifact is empty. Check artifacts only on successful
			// reconcile.
			if !tt.wantErr {
				g.Expect(obj.Status.Artifact).To(MatchArtifact(artifact.DeepCopy()))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, tt.cache)
			}
		})
	}
}

func TestHelmRepositoryReconciler_reconcileSubRecs(t *testing.T) {
	// Helper to build simple helmRepositoryReconcileFunc with result and error.
	buildReconcileFuncs := func(r sreconcile.Result, e error) helmRepositoryReconcileFunc {
		return func(ctx context.Context, sp *patch.SerialPatcher, obj *helmv1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
			return r, e
		}
	}

	tests := []struct {
		name               string
		generation         int64
		observedGeneration int64
		reconcileFuncs     []helmRepositoryReconcileFunc
		wantResult         sreconcile.Result
		wantErr            bool
		assertConditions   []metav1.Condition
	}{
		{
			name: "successful reconciliations",
			reconcileFuncs: []helmRepositoryReconcileFunc{
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
				func(ctx context.Context, sp *patch.SerialPatcher, obj *helmv1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
					return sreconcile.ResultSuccess, nil
				},
				func(ctx context.Context, sp *patch.SerialPatcher, obj *helmv1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, meta.ReconcilingCondition, meta.ProgressingReason, "creating artifact")
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
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

			r := &HelmRepositoryReconciler{
				Client:       fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme()).Build(),
				patchOptions: getPatchOptions(helmRepositoryReadyCondition.Owned, "sc"),
			}
			obj := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Status: helmv1.HelmRepositoryStatus{
					ObservedGeneration: tt.observedGeneration,
				},
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			ctx := context.TODO()
			sp := patch.NewSerialPatcher(obj, r.Client)

			gotRes, gotErr := r.reconcile(ctx, sp, obj, tt.reconcileFuncs)
			g.Expect(gotErr != nil).To(Equal(tt.wantErr))
			g.Expect(gotRes).To(Equal(tt.wantResult))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmRepositoryReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *helmv1.HelmRepository)
		assertConditions []metav1.Condition
	}{
		{
			name: "positive conditions only",
			beforeFunc: func(obj *helmv1.HelmRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *helmv1.HelmRepository) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
				conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory")
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error"),
			},
		},
		{
			name: "mixed positive and negative conditions",
			beforeFunc: func(obj *helmv1.HelmRepository) {
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

			obj := &helmv1.HelmRepository{
				TypeMeta: metav1.TypeMeta{
					Kind:       helmv1.HelmRepositoryKind,
					APIVersion: "source.toolkit.fluxcd.io/v1beta2",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "helmrepo",
					Namespace: "foo",
				},
			}
			clientBuilder := fake.NewClientBuilder()
			clientBuilder.WithObjects(obj)
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
				summarize.WithConditions(helmRepositoryReadyCondition),
				summarize.WithReconcileResult(recResult),
				summarize.WithReconcileError(retErr),
				summarize.WithIgnoreNotFound(),
				summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetRequeueAfter()}),
				summarize.WithPatchFieldOwner("source-controller"),
			}
			_, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

			key := client.ObjectKeyFromObject(obj)
			g.Expect(c.Get(ctx, key, obj)).ToNot(HaveOccurred())
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmRepositoryReconciler_notify(t *testing.T) {
	var aSize int64 = 30000
	tests := []struct {
		name             string
		res              sreconcile.Result
		resErr           error
		oldObjBeforeFunc func(obj *helmv1.HelmRepository)
		newObjBeforeFunc func(obj *helmv1.HelmRepository)
		wantEvent        string
	}{
		{
			name:   "error - no event",
			res:    sreconcile.ResultEmpty,
			resErr: errors.New("some error"),
		},
		{
			name:   "new artifact with nil size",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: nil}
			},
			wantEvent: "Normal NewArtifact stored fetched index of unknown size",
		},
		{
			name:   "new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
			},
			wantEvent: "Normal NewArtifact stored fetched index of size",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored fetched index of size",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Digest: "bbb", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored fetched index of size",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *helmv1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &helmv1.HelmRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &HelmRepositoryReconciler{
				EventRecorder: recorder,
				patchOptions:  getPatchOptions(helmRepositoryReadyCondition.Owned, "sc"),
			}
			chartRepo := repository.ChartRepository{
				URL: "some-address",
			}
			reconciler.notify(ctx, oldObj, newObj, &chartRepo, tt.res, tt.resErr)

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

func TestHelmRepositoryReconciler_ReconcileTypeUpdatePredicateFilter(t *testing.T) {
	g := NewWithT(t)

	testServer, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(testServer.Root())

	g.Expect(testServer.PackageChart("testdata/charts/helmchart")).To(Succeed())
	g.Expect(testServer.GenerateIndex()).To(Succeed())

	testServer.Start()
	defer testServer.Stop()

	obj := &helmv1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: helmv1.HelmRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      testServer.URL(),
		},
	}
	g.Expect(testEnv.CreateAndWait(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmRepository to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) && obj.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration &&
			obj.Generation == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	// Check if the object status is valid.
	condns := &conditionscheck.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker := conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	// kstatus client conformance check.
	u, err := patch.ToUnstructured(obj)
	g.Expect(err).ToNot(HaveOccurred())
	res, err := kstatus.Compute(u)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Status).To(Equal(kstatus.CurrentStatus))

	// Switch to a OCI helm repository type
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Data: map[string][]byte{
			"username": []byte(testRegistryUsername),
			"password": []byte(testRegistryPassword),
		},
	}
	g.Expect(testEnv.CreateAndWait(ctx, secret)).To(Succeed())

	obj.Spec.Type = helmv1.HelmRepositoryTypeOCI
	obj.Spec.URL = fmt.Sprintf("oci://%s", testRegistryServer.registryHost)
	obj.Spec.SecretRef = &meta.LocalObjectReference{
		Name: secret.Name,
	}

	oldGen := obj.GetGeneration()
	g.Expect(testEnv.Update(ctx, obj)).To(Succeed())
	newGen := oldGen + 1

	// Wait for HelmRepository to be Ready with new generation.
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) && obj.Status.Artifact != nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		if readyCondition == nil {
			return false
		}
		return readyCondition.Status == metav1.ConditionTrue &&
			newGen == readyCondition.ObservedGeneration &&
			newGen == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	// Check if the object status is valid.
	condns = &conditionscheck.Conditions{NegativePolarity: helmRepositoryOCINegativeConditions}
	checker = conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmRepository to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestHelmRepositoryReconciler_ReconcileSpecUpdatePredicateFilter(t *testing.T) {
	g := NewWithT(t)

	testServer, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(testServer.Root())

	g.Expect(testServer.PackageChart("testdata/charts/helmchart")).To(Succeed())
	g.Expect(testServer.GenerateIndex()).To(Succeed())

	testServer.Start()
	defer testServer.Stop()

	obj := &helmv1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: helmv1.HelmRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      testServer.URL(),
		},
	}
	g.Expect(testEnv.CreateAndWait(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmRepository to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) && obj.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration &&
			obj.Generation == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	// Check if the object status is valid.
	condns := &conditionscheck.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker := conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	// kstatus client conformance check.
	u, err := patch.ToUnstructured(obj)
	g.Expect(err).ToNot(HaveOccurred())
	res, err := kstatus.Compute(u)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Status).To(Equal(kstatus.CurrentStatus))

	// Change spec Interval to validate spec update
	obj.Spec.Interval = metav1.Duration{Duration: interval + time.Second}
	oldGen := obj.GetGeneration()
	g.Expect(testEnv.Update(ctx, obj)).To(Succeed())
	newGen := oldGen + 1

	// Wait for HelmRepository to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) && obj.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		return readyCondition.Status == metav1.ConditionTrue &&
			newGen == readyCondition.ObservedGeneration &&
			newGen == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	// Check if the object status is valid.
	condns = &conditionscheck.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker = conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmRepository to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestHelmRepositoryReconciler_InMemoryCaching(t *testing.T) {
	g := NewWithT(t)
	testCache.Clear()

	testServer, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(testServer.Root())

	g.Expect(testServer.PackageChartWithVersion("testdata/charts/helmchart", "0.1.0")).To(Succeed())
	g.Expect(testServer.GenerateIndex()).To(Succeed())

	testServer.Start()
	defer testServer.Stop()

	ns, err := testEnv.CreateNamespace(ctx, "helmrepository")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	helmRepo := &helmv1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-",
			Namespace:    ns.Name,
		},
		Spec: helmv1.HelmRepositorySpec{
			URL: testServer.URL(),
		},
	}
	g.Expect(testEnv.CreateAndWait(ctx, helmRepo)).To(Succeed())

	key := client.ObjectKey{Name: helmRepo.Name, Namespace: helmRepo.Namespace}
	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, helmRepo); err != nil {
			return false
		}
		return len(helmRepo.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmRepository to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, helmRepo); err != nil {
			return false
		}
		if !conditions.IsReady(helmRepo) || helmRepo.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(helmRepo, meta.ReadyCondition)
		return helmRepo.Generation == readyCondition.ObservedGeneration &&
			helmRepo.Generation == helmRepo.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	err = testEnv.Get(ctx, key, helmRepo)
	g.Expect(err).ToNot(HaveOccurred())
	_, cacheHit := testCache.Get(helmRepo.GetArtifact().Path)
	g.Expect(cacheHit).To(BeTrue())
}
