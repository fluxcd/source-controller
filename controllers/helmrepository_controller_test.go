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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	. "github.com/onsi/gomega"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
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
	condns := &status.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker := status.NewChecker(testEnv.Client, condns)
	checker.CheckErr(ctx, obj)

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
				revisions := []string{"a", "b", "c", "d"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
						Path:     fmt.Sprintf("/reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := testStorage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}
					if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0o640); err != nil {
						return err
					}
					if n != len(revisions)-1 {
						time.Sleep(time.Second * 1)
					}
				}
				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			assertArtifact: &sourcev1.Artifact{
				Path:     "/reconcile-storage/d.txt",
				Revision: "d",
				Checksum: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
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
				if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0o640); err != nil {
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
				Size:     int64p(int64(len("file"))),
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
		beforeFunc       func(t *WithT, obj *sourcev1.HelmRepository, checksum string)
		afterFunc        func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository)
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
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				t.Expect(chartRepo.Checksum).ToNot(BeEmpty())
				t.Expect(chartRepo.CachePath).ToNot(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "basic-auth"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				t.Expect(chartRepo.Checksum).ToNot(BeEmpty())
				t.Expect(chartRepo.CachePath).ToNot(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				t.Expect(chartRepo.Checksum).ToNot(BeEmpty())
				t.Expect(chartRepo.CachePath).ToNot(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-ca"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to create TLS client config with secret data: cannot append certificate into certificate pool: invalid caFile"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).To(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Invalid URL makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "first path segment in URL cannot contain colon"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).To(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Unsupported scheme makes FetchFailed=True and returns stalling error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.URL = strings.ReplaceAll(obj.Spec.URL, "http://", "ftp://")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FailedReason, "scheme \"ftp\" not supported"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).To(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "Missing secret returns FetchFailed=True and returns error",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "secrets \"non-existing\" not found"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).To(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
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
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "malformed-basic-auth"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "required fields 'username' and 'password"),
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// No repo index due to fetch fail.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).To(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
				t.Expect(artifact.Revision).To(BeEmpty())
			},
		},
		{
			name:     "cached index with same checksum",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: checksum,
					Checksum: checksum,
				}
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				// chartRepo.Checksum isn't populated, artifact.Checksum is
				// populated from the cached repo index data.
				t.Expect(chartRepo.Checksum).To(BeEmpty())
				t.Expect(chartRepo.CachePath).ToNot(BeEmpty())
				t.Expect(artifact.Checksum).To(Equal(obj.Status.Artifact.Checksum))
				t.Expect(artifact.Revision).To(Equal(obj.Status.Artifact.Revision))
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:     "cached index with different checksum",
			protocol: "http",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, checksum string) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: checksum,
					Checksum: "foo",
				}
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo repository.ChartRepository) {
				t.Expect(chartRepo.Checksum).ToNot(BeEmpty())
				t.Expect(chartRepo.CachePath).ToNot(BeEmpty())
				t.Expect(artifact.Checksum).To(BeEmpty())
				t.Expect(artifact.Revision).To(Equal(obj.Status.Artifact.Revision))
			},
			want: sreconcile.ResultSuccess,
		},
	}

	for _, tt := range tests {
		obj := &sourcev1.HelmRepository{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "auth-strategy-",
			},
			Spec: sourcev1.HelmRepositorySpec{
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
			case "https":
				g.Expect(server.StartTLS(tt.server.publicKey, tt.server.privateKey, tt.server.ca, "example.com")).To(Succeed())
				defer server.Stop()
				obj.Spec.URL = server.URL()
			default:
				t.Fatalf("unsupported protocol %q", tt.protocol)
			}

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			// Calculate the artifact checksum for valid repos configurations.
			clientOpts := []helmgetter.Option{
				helmgetter.WithURL(server.URL()),
			}
			var newChartRepo *repository.ChartRepository
			var tOpts *tls.Config
			validSecret := true
			if secret != nil {
				// Extract the client options from secret, ignoring any invalid
				// value. validSecret is used to determine if the indexChecksum
				// should be calculated below.
				var cOpts []helmgetter.Option
				var serr error
				cOpts, serr = getter.ClientOptionsFromSecret(*secret)
				if serr != nil {
					validSecret = false
				}
				clientOpts = append(clientOpts, cOpts...)
				tOpts, serr = getter.TLSClientConfigFromSecret(*secret, server.URL())
				if serr != nil {
					validSecret = false
				}
				newChartRepo, err = repository.NewChartRepository(obj.Spec.URL, "", testGetters, tOpts, clientOpts)
			} else {
				newChartRepo, err = repository.NewChartRepository(obj.Spec.URL, "", testGetters, nil, nil)
			}
			g.Expect(err).ToNot(HaveOccurred())

			// NOTE: checksum will be empty in beforeFunc for invalid repo
			// configurations as the client can't get the repo.
			var indexChecksum string
			if validSecret {
				indexChecksum, err = newChartRepo.CacheIndex()
				g.Expect(err).ToNot(HaveOccurred())
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, indexChecksum)
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
				tt.afterFunc(g, obj, artifact, chartRepo)
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
			name: "Archiving artifact to storage makes ArtifactInStorage=True",
			beforeFunc: func(t *WithT, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index *repository.ChartRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
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
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
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
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
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
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'existing'"),
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

			tmpDir := t.TempDir()

			// Create an empty cache file.
			cachePath := filepath.Join(tmpDir, "index.yaml")
			cacheFile, err := os.Create(cachePath)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cacheFile.Close()).ToNot(HaveOccurred())

			chartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", testGetters, nil, nil)
			g.Expect(err).ToNot(HaveOccurred())
			chartRepo.CachePath = cachePath

			artifact := testStorage.NewArtifactFor(obj.Kind, obj, "existing", "foo.tar.gz")
			// Checksum of the index file calculated by the ChartRepository.
			artifact.Checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, artifact, chartRepo)
			}

			got, err := r.reconcileArtifact(context.TODO(), obj, &artifact, chartRepo)
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

func TestHelmRepositoryReconciler_reconcileSubRecs(t *testing.T) {
	// Helper to build simple helmRepositoryReconcileFunc with result and error.
	buildReconcileFuncs := func(r sreconcile.Result, e error) helmRepositoryReconcileFunc {
		return func(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error) {
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewGeneration", "reconciling new object generation (3)"),
			},
		},
		{
			name: "failed reconciliation",
			reconcileFuncs: []helmRepositoryReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
		},
		{
			name: "multiple object status conditions mutations",
			reconcileFuncs: []helmRepositoryReconcileFunc{
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
			reconcileFuncs: []helmRepositoryReconcileFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultRequeue,
			wantErr:    false,
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

func TestHelmRepositoryReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmRepository)
		assertConditions []metav1.Condition
	}{
		{
			name: "positive conditions only",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
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
			beforeFunc: func(obj *sourcev1.HelmRepository) {
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

			obj := &sourcev1.HelmRepository{
				TypeMeta: metav1.TypeMeta{
					Kind:       sourcev1.HelmRepositoryKind,
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

			patchHelper, err := patch.NewHelper(obj, c)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			recResult := sreconcile.ResultSuccess
			var retErr error

			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), patchHelper)
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
		oldObjBeforeFunc func(obj *sourcev1.HelmRepository)
		newObjBeforeFunc func(obj *sourcev1.HelmRepository)
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
			newObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: nil}
			},
			wantEvent: "Normal NewArtifact stored fetched index of unknown size",
		},
		{
			name:   "new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
			},
			wantEvent: "Normal NewArtifact stored fetched index of size",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored fetched index of size",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Checksum: "bbb", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored fetched index of size",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy", Size: &aSize}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.HelmRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &HelmRepositoryReconciler{
				EventRecorder: recorder,
			}
			chartRepo := repository.ChartRepository{
				URL: "some-address",
			}
			reconciler.notify(ctx, oldObj, newObj, chartRepo, tt.res, tt.resErr)

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
	condns := &status.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker := status.NewChecker(testEnv.Client, condns)
	checker.CheckErr(ctx, obj)

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

	obj.Spec.Type = sourcev1.HelmRepositoryTypeOCI
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
	condns = &status.Conditions{NegativePolarity: helmRepositoryOCINegativeConditions}
	checker = status.NewChecker(testEnv.Client, condns)
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

func TestHelmRepositoryReconciler_ReconcileSpecUpdatePredicateFilter(t *testing.T) {
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
	condns := &status.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker := status.NewChecker(testEnv.Client, condns)
	checker.CheckErr(ctx, obj)

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
	condns = &status.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
	checker = status.NewChecker(testEnv.Client, condns)
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
