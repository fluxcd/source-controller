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

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
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

	obj := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.HelmRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      testServer.URL(),
		},
	}
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
	condns := &status.Conditions{NegativePolarity: helmRepoReadyDepsNegative}
	checker := status.NewChecker(testEnv.Client, testEnv.GetScheme(), condns)
	checker.CheckErr(ctx, obj)

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmRepository to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestHelmRepositoryReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmRepository, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.HelmRepository, storage *Storage) error {
				revisions := []string{"a", "b", "c"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
						Path:     fmt.Sprintf("/reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := testStorage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}
					if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0644); err != nil {
						return err
					}
				}
				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			assertArtifact: &sourcev1.Artifact{
				Path:     "/reconcile-storage/c.txt",
				Revision: "c",
				Checksum: "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
				URL:      testStorage.Hostname + "/reconcile-storage/c.txt",
			},
			assertPaths: []string{
				"/reconcile-storage/c.txt",
				"!/reconcile-storage/b.txt",
				"!/reconcile-storage/a.txt",
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.HelmRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "/reconcile-storage/invalid.txt",
					Revision: "d",
				}
				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NoArtifact", "no artifact for resource in storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.HelmRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "/reconcile-storage/hostname.txt",
					Revision: "f",
					Checksum: "3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
					URL:      "http://outdated.com/reconcile-storage/hostname.txt",
				}
				if err := testStorage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0644); err != nil {
					return err
				}
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"/reconcile-storage/hostname.txt",
			},
			assertArtifact: &sourcev1.Artifact{
				Path:     "/reconcile-storage/hostname.txt",
				Revision: "f",
				Checksum: "3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
				URL:      testStorage.Hostname + "/reconcile-storage/hostname.txt",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
			}

			obj := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
			}
			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			var chartRepo repository.ChartRepository
			var artifact sourcev1.Artifact

			got, err := r.reconcileStorage(context.TODO(), obj, &artifact, &chartRepo)
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
		secret           *corev1.Secret
		beforeFunc       func(t *WithT, obj *sourcev1.HelmRepository)
		afterFunc        func(t *WithT, obj *sourcev1.HelmRepository)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name:     "HTTP without secretRef makes ArtifactOutdated=True",
			protocol: "http",
			want:     sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "basic-auth"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-ca"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "can't create TLS config for client: failed to append certificates from file"),
			},
		},
		{
			name:     "Invalid URL makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "first path segment in URL cannot contain colon"),
			},
		},
		{
			name:     "Unsupported scheme makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "ftp://")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "scheme \"ftp\" not supported"),
			},
		},
		{
			name:     "Missing secret returns FetchFailed=True and returns error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "secrets \"non-existing\" not found"),
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "malformed-basic-auth"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "required fields 'username' and 'password"),
			},
		},
	}

	for _, tt := range tests {
		obj := &sourcev1.HelmRepository{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "auth-strategy-",
			},
			Spec: sourcev1.HelmRepositorySpec{
				Interval: metav1.Duration{Duration: interval},
				Timeout:  &metav1.Duration{Duration: interval},
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
			case "https":
				g.Expect(server.StartTLS(tt.server.publicKey, tt.server.privateKey, tt.server.ca, "example.com")).To(Succeed())
				defer server.Stop()
				obj.Spec.URL = server.URL()
			default:
				t.Fatalf("unsupported protocol %q", tt.protocol)
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj)
			}

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			r := &HelmRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        builder.Build(),
				Storage:       testStorage,
				Getters:       testGetters,
			}

			var chartRepo repository.ChartRepository
			var artifact sourcev1.Artifact
			got, err := r.reconcileSource(context.TODO(), obj, &artifact, &chartRepo)
			defer os.Remove(chartRepo.CachePath)

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestHelmRepositoryReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository)
		afterFunc        func(t *WithT, obj *sourcev1.HelmRepository)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archiving artifact to storage makes Ready=True",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision 'existing'"),
			},
		},
		{
			name: "Up-to-date artifact should not update status",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Status.Artifact = artifact.DeepCopy()
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Removes ArtifactOutdatedCondition after creating a new artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision 'existing'"),
			},
		},
		{
			name: "Creates latest symlink to the created artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "index.yaml")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision 'existing'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
			}

			obj := &sourcev1.HelmRepository{
				TypeMeta: metav1.TypeMeta{
					Kind: sourcev1.HelmRepositoryKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
					Namespace:    "default",
				},
				Spec: sourcev1.HelmRepositorySpec{
					Timeout: &metav1.Duration{Duration: timeout},
					URL:     "https://example.com/index.yaml",
				},
			}

			tmpDir, err := os.MkdirTemp("", "test-reconcile-artifact-")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			// Create an empty cache file.
			cachePath := filepath.Join(tmpDir, "index.yaml")
			cacheFile, err := os.Create(cachePath)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cacheFile.Close()).ToNot(HaveOccurred())

			chartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", testGetters, nil)
			g.Expect(err).ToNot(HaveOccurred())
			chartRepo.CachePath = cachePath

			artifact := testStorage.NewArtifactFor(obj.Kind, obj, "existing", "foo.tar.gz")
			// Checksum of the index file calculated by the ChartRepository.
			artifact.Checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, artifact, chartRepo)
			}
			dlog := log.NewDelegatingLogSink(log.NullLogSink{})
			nullLogger := logr.New(dlog)
			got, err := r.reconcileArtifact(logr.NewContext(ctx, nullLogger), obj, &artifact, chartRepo)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			// On error, artifact is empty. Check artifacts only on successful
			// reconcile.
			if !tt.wantErr {
				g.Expect(obj.Status.Artifact).To(MatchArtifact(artifact.DeepCopy()))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestHelmRepositoryReconciler_summarizeAndPatch(t *testing.T) {
	tests := []struct {
		name             string
		generation       int64
		beforeFunc       func(obj *sourcev1.HelmRepository)
		result           sreconcile.Result
		reconcileErr     error
		wantErr          bool
		afterFunc        func(t *WithT, obj *sourcev1.HelmRepository)
		assertConditions []metav1.Condition
	}{
		// Success/Fail indicates if a reconciliation succeeded or failed. On
		// a successful reconciliation, the object generation is expected to
		// match the observed generation in the object status.
		// All the cases have some Ready condition set, even if a test case is
		// unrelated to the conditions, because it's neseccary for a valid
		// status.
		{
			name:       "Success, no extra conditions",
			generation: 4,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).To(Equal(int64(4)))
			},
		},
		{
			name:       "Success, Ready=True",
			generation: 5,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "created")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "created"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).To(Equal(int64(5)))
			},
		},
		{
			name:       "Success, removes reconciling for successful result",
			generation: 2,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkReconciling(obj, "NewRevision", "new index version")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "stored artifact")
			},
			result:  sreconcile.ResultSuccess,
			wantErr: false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).To(Equal(int64(2)))
			},
		},
		{
			name: "Success, record reconciliation request",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "now",
				}
				obj.SetAnnotations(annotations)
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
			},
			generation: 3,
			result:     sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.LastHandledReconcileAt).To(Equal("now"))
				t.Expect(obj.Status.ObservedGeneration).To(Equal(int64(3)))
			},
		},
		{
			name:       "Fail, with multiple conditions ArtifactOutdated=True,Reconciling=True",
			generation: 7,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
				conditions.MarkReconciling(obj, "NewRevision", "new index revision")
			},
			reconcileErr: fmt.Errorf("failed to create dir"),
			wantErr:      true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).ToNot(Equal(int64(7)))
			},
		},
		{
			name:       "Success, with subreconciler stalled error",
			generation: 9,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.FetchFailedCondition, "failed to construct helm client")
			},
			reconcileErr: &serror.Stalling{Err: fmt.Errorf("some error"), Reason: "some reason"},
			wantErr:      false,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.FetchFailedCondition, "failed to construct helm client"),
				*conditions.TrueCondition(meta.StalledCondition, "some reason", "some error"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.FetchFailedCondition, "failed to construct helm client"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).To(Equal(int64(9)))
			},
		},
		{
			name:       "Fail, no error but requeue requested",
			generation: 3,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "test-msg")
			},
			result: sreconcile.ResultRequeue,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, meta.FailedReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository) {
				t.Expect(obj.Status.ObservedGeneration).ToNot(Equal(int64(3)))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			r := &HelmRepositoryReconciler{
				Client:        builder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
			}
			obj := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Spec: sourcev1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: 5 * time.Second},
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			g.Expect(r.Create(ctx, obj)).To(Succeed())
			patchHelper, err := patch.NewHelper(obj, r.Client)
			g.Expect(err).ToNot(HaveOccurred())

			_, gotErr := r.summarizeAndPatch(ctx, obj, patchHelper, tt.result, tt.reconcileErr)
			g.Expect(gotErr != nil).To(Equal(tt.wantErr))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}

			// Check if the object status is valid.
			condns := &status.Conditions{NegativePolarity: helmRepoReadyDepsNegative}
			checker := status.NewChecker(r.Client, testEnv.GetScheme(), condns)
			checker.CheckErr(ctx, obj)
		})
	}
}

func TestHelmRepositoryReconciler_reconcileSubRecs(t *testing.T) {
	// Helper to build simple helmRepoReconcilerFunc with result and error.
	buildReconcileFuncs := func(r sreconcile.Result, e error) helmRepoReconcilerFunc {
		return func(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
			return r, e
		}
	}

	tests := []struct {
		name               string
		generation         int64
		observedGeneration int64
		reconcileFuncs     []helmRepoReconcilerFunc
		wantResult         sreconcile.Result
		wantErr            bool
		assertConditions   []metav1.Condition
	}{
		{
			name: "successful reconciliations",
			reconcileFuncs: []helmRepoReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
		},
		{
			name:               "successful reconciliation with generation difference",
			generation:         3,
			observedGeneration: 2,
			reconcileFuncs: []helmRepoReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewGeneration", "reconciling new generation 3"),
			},
		},
		{
			name: "failed reconciliation",
			reconcileFuncs: []helmRepoReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
		},
		{
			name: "multiple object status conditions mutations",
			reconcileFuncs: []helmRepoReconcilerFunc{
				func(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
					return sreconcile.ResultSuccess, nil
				},
				func(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, meta.ReconcilingCondition, "Progressing", "creating artifact")
					return sreconcile.ResultSuccess, nil
				},
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "Progressing", "creating artifact"),
			},
		},
		{
			name: "subrecs with one result=Requeue, no error",
			reconcileFuncs: []helmRepoReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultRequeue,
			wantErr:    false,
		},
		{
			name: "subrecs with error before result=Requeue",
			reconcileFuncs: []helmRepoReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmRepositoryReconciler{}
			obj := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Status: sourcev1.HelmRepositoryStatus{
					ObservedGeneration: tt.observedGeneration,
				},
			}

			ctx := context.TODO()

			gotRes, gotErr := r.reconcile(ctx, obj, tt.reconcileFuncs)
			g.Expect(gotErr != nil).To(Equal(tt.wantErr))
			g.Expect(gotRes).To(Equal(tt.wantResult))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}
