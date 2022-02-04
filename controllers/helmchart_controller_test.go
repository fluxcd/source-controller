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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/helm/chart"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
)

func TestHelmChartReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	const (
		chartName    = "helmchart"
		chartVersion = "0.2.0"
		chartPath    = "testdata/charts/helmchart"
	)

	server, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(server.Root())

	g.Expect(server.PackageChartWithVersion(chartPath, chartVersion)).To(Succeed())
	g.Expect(server.GenerateIndex()).To(Succeed())

	server.Start()
	defer server.Stop()

	ns, err := testEnv.CreateNamespace(ctx, "helmchart")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	repository := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-",
			Namespace:    ns.Name,
		},
		Spec: sourcev1.HelmRepositorySpec{
			URL: server.URL(),
		},
	}
	g.Expect(testEnv.CreateAndWait(ctx, repository)).To(Succeed())

	obj := &sourcev1.HelmChart{
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
	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmChart to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) || obj.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		return obj.Generation == readyCondition.ObservedGeneration &&
			obj.Generation == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	// Check if the object status is valid.
	condns := &status.Conditions{NegativePolarity: helmChartReadyConditions.NegativePolarity}
	checker := status.NewChecker(testEnv.Client, testEnv.GetScheme(), condns)
	checker.CheckErr(ctx, obj)

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

	// Wait for HelmChart to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestHelmChartReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmChart, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.HelmChart, storage *Storage) error {
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
			beforeFunc: func(obj *sourcev1.HelmChart, storage *Storage) error {
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
			beforeFunc: func(obj *sourcev1.HelmChart, storage *Storage) error {
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

			r := &HelmChartReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
			}

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
			}
			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			got, err := r.reconcileStorage(context.TODO(), obj, nil)
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

func TestHelmChartReconciler_reconcileSource(t *testing.T) {
	g := NewWithT(t)

	tmpDir, err := os.MkdirTemp("", "reconcile-tarball-")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	storage, err := NewStorage(tmpDir, "example.com", timeout)
	g.Expect(err).ToNot(HaveOccurred())

	gitArtifact := &sourcev1.Artifact{
		Revision: "mock-ref/abcdefg12345678",
		Path:     "mock.tgz",
	}
	g.Expect(storage.Archive(gitArtifact, "testdata/charts", nil)).To(Succeed())

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
					*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewChart", "pulled 'helmchart' chart with version '0.1.0'"),
				}))
			},
			cleanFunc: func(g *WithT, build *chart.Build) {
				g.Expect(os.Remove(build.Path)).To(Succeed())
			},
		},
		{
			name: "Error on unavailable source",
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Spec.SourceRef = sourcev1.LocalHelmChartSourceReference{
					Name: "unavailable",
					Kind: sourcev1.GitRepositoryKind,
				}
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Event{Err: errors.New("gitrepositories.source.toolkit.fluxcd.io \"unavailable\" not found")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "SourceUnavailable", "failed to get source: gitrepositories.source.toolkit.fluxcd.io \"unavailable\" not found"),
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
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("unsupported source kind 'Unsupported'")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "SourceUnavailable", "failed to get source: unsupported source kind"),
				}))
			},
		},
		//{
		//	name: "Error on transient build error",
		//},
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
			},
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Stalling{Err: errors.New("values files merge error: no values file found at path")},
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.BuildFailedCondition, "ValuesFilesError", "values files merge error: no values file found at path"),
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
			},
			want: sreconcile.ResultRequeue,
			assertFunc: func(g *WithT, build chart.Build, obj sourcev1.HelmChart) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.ObservedSourceArtifactRevision).To(Equal("foo"))
				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, "NoSourceArtifact", "no artifact available"),
				}))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fake.NewClientBuilder()
			if tt.source != nil {
				clientBuilder.WithRuntimeObjects(tt.source)
			}

			r := &HelmChartReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       storage,
			}

			obj := sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "chart",
					Namespace: "default",
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

			got, err := r.reconcileSource(context.TODO(), &obj, &b)

			g.Expect(err != nil).To(Equal(tt.wantErr != nil))
			if tt.wantErr != nil {
				g.Expect(reflect.TypeOf(err).String()).To(Equal(reflect.TypeOf(tt.wantErr).String()))
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr.Error()))
			}
			g.Expect(got).To(Equal(tt.want))

			if tt.assertFunc != nil {
				tt.assertFunc(g, b, obj)
			}
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
				obj.Status.Artifact = &sourcev1.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
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
				obj.Status.Artifact = &sourcev1.Artifact{Path: chartName + "-" + chartVersion + ".tgz"}
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
			wantErr: &serror.Event{Err: errors.New("failed to get secret 'invalid'")},
			assertFunc: func(g *WithT, obj *sourcev1.HelmChart, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())

				g.Expect(obj.Status.Conditions).To(conditions.MatchConditions([]metav1.Condition{
					*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret 'invalid'"),
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

			clientBuilder := fake.NewClientBuilder()
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
					Artifact: &sourcev1.Artifact{
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

func TestHelmChartReconciler_buildFromTarballArtifact(t *testing.T) {
	g := NewWithT(t)

	tmpDir, err := os.MkdirTemp("", "reconcile-tarball-")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	storage, err := NewStorage(tmpDir, "example.com", timeout)
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
				g.Expect(build.ResolvedDependencies).To(Equal(3))
				g.Expect(build.Path).To(BeARegularFile())
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
				g.Expect(build.Path).To(Equal(storage.LocalPath(*cachedArtifact.DeepCopy())))
				g.Expect(build.Path).To(BeARegularFile())
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
			wantErr: &serror.Event{Err: errors.New("no such file or directory")},
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())
			},
		},
		{
			name:    "Invalid artifact type",
			source:  *yamlArtifact,
			want:    sreconcile.ResultEmpty,
			wantErr: &serror.Event{Err: errors.New("artifact untar error: requires gzip-compressed body")},
			assertFunc: func(g *WithT, build chart.Build) {
				g.Expect(build.Complete()).To(BeFalse())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				Client:        fake.NewClientBuilder().Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       storage,
				Getters:       testGetters,
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
			name:  "Copying artifact to storage from build makes Ready=True",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).To(Equal("bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
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
				obj.Status.Artifact = &sourcev1.Artifact{
					Path: "testdata/charts/helmchart-0.1.0.tgz",
				}
			},
			want: sreconcile.ResultSuccess,
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
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
			beforeFunc: func(obj *sourcev1.HelmChart) {
				obj.Status.ObservedChartName = "helmchart"
				obj.Status.Artifact = &sourcev1.Artifact{
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
				*conditions.TrueCondition(meta.ReadyCondition, sourcev1.ChartPackageSucceededReason, "packaged 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Removes ArtifactOutdatedCondition after creating new artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
			beforeFunc: func(obj *sourcev1.HelmChart) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.HelmChart) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).To(Equal("bbdf96023c912c393b49d5238e227576ed0d20d1bb145d7476d817b80e20c11a"))
				t.Expect(obj.GetArtifact().Revision).To(Equal("0.1.0"))
				t.Expect(obj.Status.URL).ToNot(BeEmpty())
				t.Expect(obj.Status.ObservedChartName).To(Equal("helmchart"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
		{
			name:  "Creates latest symlink to the created artifact",
			build: mockChartBuild("helmchart", "0.1.0", "testdata/charts/helmchart-0.1.0.tgz"),
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
				*conditions.TrueCondition(meta.ReadyCondition, sourcev1.ChartPullSucceededReason, "pulled 'helmchart' chart with version '0.1.0'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &HelmChartReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
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

			got, err := r.reconcileArtifact(ctx, obj, tt.build)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestHelmChartReconciler_getHelmRepositorySecret(t *testing.T) {
	mock := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "foo",
		},
		Data: map[string][]byte{
			"key": []byte("bar"),
		},
	}
	clientBuilder := fake.NewClientBuilder()
	clientBuilder.WithObjects(mock)

	r := &HelmChartReconciler{
		Client: clientBuilder.Build(),
	}

	tests := []struct {
		name       string
		repository *sourcev1.HelmRepository
		want       *corev1.Secret
		wantErr    bool
	}{
		{
			name: "Existing secret reference",
			repository: &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: mock.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					SecretRef: &meta.LocalObjectReference{
						Name: mock.Name,
					},
				},
			},
			want: mock,
		},
		{
			name: "Empty secret reference",
			repository: &sourcev1.HelmRepository{
				Spec: sourcev1.HelmRepositorySpec{
					SecretRef: nil,
				},
			},
			want: nil,
		},
		{
			name: "Error on client error",
			repository: &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "different",
				},
				Spec: sourcev1.HelmRepositorySpec{
					SecretRef: &meta.LocalObjectReference{
						Name: mock.Name,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := r.getHelmRepositorySecret(context.TODO(), tt.repository)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestHelmChartReconciler_getSource(t *testing.T) {
	mocks := []client.Object{
		&sourcev1.HelmRepository{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.HelmRepositoryKind,
				APIVersion: "source.toolkit.fluxcd.io/v1beta2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "helmrepository",
				Namespace: "foo",
			},
		},
		&sourcev1.GitRepository{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.GitRepositoryKind,
				APIVersion: "source.toolkit.fluxcd.io/v1beta2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gitrepository",
				Namespace: "foo",
			},
		},
		&sourcev1.Bucket{
			TypeMeta: metav1.TypeMeta{
				Kind:       sourcev1.BucketKind,
				APIVersion: "source.toolkit.fluxcd.io/v1beta2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bucket",
				Namespace: "foo",
			},
		},
	}
	clientBuilder := fake.NewClientBuilder()
	clientBuilder.WithObjects(mocks...)

	r := &HelmChartReconciler{
		Client: clientBuilder.Build(),
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
	// Helper to build simple helmChartReconcilerFunc with result and error.
	buildReconcileFuncs := func(r sreconcile.Result, e error) helmChartReconcilerFunc {
		return func(_ context.Context, _ *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
			return r, e
		}
	}

	tests := []struct {
		name               string
		generation         int64
		observedGeneration int64
		reconcileFuncs     []helmChartReconcilerFunc
		wantResult         sreconcile.Result
		wantErr            bool
		assertConditions   []metav1.Condition
	}{
		{
			name: "successful reconciliations",
			reconcileFuncs: []helmChartReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultSuccess,
			wantErr:    false,
		},
		{
			name:               "successful reconciliation with generation difference",
			generation:         3,
			observedGeneration: 2,
			reconcileFuncs: []helmChartReconcilerFunc{
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
			reconcileFuncs: []helmChartReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultEmpty, fmt.Errorf("some error")),
			},
			wantResult: sreconcile.ResultEmpty,
			wantErr:    true,
		},
		{
			name: "multiple object status conditions mutations",
			reconcileFuncs: []helmChartReconcilerFunc{
				func(_ context.Context, obj *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
					conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
					return sreconcile.ResultSuccess, nil
				},
				func(_ context.Context, obj *sourcev1.HelmChart, _ *chart.Build) (sreconcile.Result, error) {
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
			reconcileFuncs: []helmChartReconcilerFunc{
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
				buildReconcileFuncs(sreconcile.ResultRequeue, nil),
				buildReconcileFuncs(sreconcile.ResultSuccess, nil),
			},
			wantResult: sreconcile.ResultRequeue,
			wantErr:    false,
		},
		{
			name: "subrecs with error before result=Requeue",
			reconcileFuncs: []helmChartReconcilerFunc{
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

			r := &HelmChartReconciler{}
			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Status: sourcev1.HelmChartStatus{
					ObservedGeneration: tt.observedGeneration,
				},
			}

			got, err := r.reconcile(context.TODO(), obj, tt.reconcileFuncs)
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
