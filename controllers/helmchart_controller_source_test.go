package controllers

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart/loader"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/helmtestserver"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

func TestHelmChartReconciler_reconcileSource(t *testing.T) {

}

func TestHelmChartReconciler_reconcileFromHelmRepository(t *testing.T) {
	g := NewWithT(t)

	versions := []string{"v0.1.0", "0.2.0", "v0.2.1", "v1.0.0-alpha", "v1.1.0", "v2.0.0"}

	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.HelmChart, sourceObj *sourcev1.HelmRepository)
		want             ctrl.Result
		wantErr          bool
		wantRevision     string
		assertConditions []metav1.Condition
	}{
		{
			name:         "Empty version (latest)",
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "v2.0.0",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version v2.0.0"),
			},
		},
		{
			name: "SemVer (any)",
			want: ctrl.Result{RequeueAfter: interval},
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Version = "*"
			},
			wantRevision: "v2.0.0",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version v2.0.0"),
			},
		},
		{
			name: "SemVer selector",
			want: ctrl.Result{RequeueAfter: interval},
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Version = "<v0.3.0"
			},
			wantRevision: "v0.2.1",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version v0.2.1"),
			},
		},
		{
			name: "Existing artifact",
			want: ctrl.Result{RequeueAfter: interval},
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Version = "<v0.3.0"
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "v0.2.1",
				}
				obj.Status.Conditions = []metav1.Condition{
					*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version v0.2.1"),
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version v0.2.1"),
			},
		},
		{
			name: "Invalid chart name",
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Chart = "invalid/helmchart"
			},
			want: ctrl.Result{},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "InvalidChartName", "Validation error: invalid chart name \"invalid/helmchart\", a valid name must be lower case letters and numbers and MAY be separated with dashes (-)"),
			},
		},
		{
			name: "Invalid repository URL",
			beforeFunc: func(_ *sourcev1.HelmChart, repository *sourcev1.HelmRepository) {
				repository.Spec.URL = "://example.com"
			},
			want: ctrl.Result{},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Invalid Helm repository URL: parse \"://example.com\": missing protocol scheme"),
			},
		},
		{
			name: "Non-existing version",
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Version = "v3.0.0"
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Could not find \"helmchart\" chart with version \"v3.0.0\": no chart version found for helmchart-v3.0.0"),
			},
		},
		{
			name: "Invalid version",
			beforeFunc: func(obj *sourcev1.HelmChart, _ *sourcev1.HelmRepository) {
				obj.Spec.Version = "invalid"
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Could not find \"helmchart\" chart with version \"invalid\": improper constraint: invalid"),
			},
		},
	}

	server, err := helmtestserver.NewTempHelmServer()
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(server.Root())
	server.Start()
	defer server.Stop()

	for _, v := range versions {
		g.Expect(server.PackageChartWithVersion("testdata/charts/helmchart", v)).To(Succeed())
	}

	g.Expect(server.GenerateIndex()).To(Succeed())

	sourceObj := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helm-repository-",
		},
		Spec: sourcev1.HelmRepositorySpec{
			URL:     server.URL(),
			Timeout: &metav1.Duration{Duration: timeout},
		},
	}

	s := runtime.NewScheme()
	utilruntime.Must(sourcev1.AddToScheme(s))

	builder := fakeclient.NewClientBuilder().WithScheme(s)
	builder.WithObjects(sourceObj)

	r := &HelmChartReconciler{
		Client:  builder.Build(),
		Storage: storage,
		Getters: testGetters,
	}

	artifact := r.Storage.NewArtifactFor(sourcev1.HelmRepositoryKind, sourceObj, "revision", "index.yaml")
	g.Expect(r.Storage.MkdirAll(artifact)).To(Succeed())
	defer r.Storage.RemoveAll(artifact)
	g.Expect(r.Storage.CopyFromPath(&artifact, filepath.Join(server.Root(), "index.yaml"))).To(Succeed())
	sourceObj.Status.Artifact = &artifact

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "from-helmrepository-",
					Namespace:    "default",
				},
				Spec: sourcev1.HelmChartSpec{
					Interval: metav1.Duration{Duration: interval},
					Chart:    "helmchart",
					Version:  "",
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: "helm-repository-",
					},
				},
			}

			sourceObj := sourceObj.DeepCopy()
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, sourceObj)
			}

			var path string
			got, err := r.reconcileFromHelmRepository(logr.NewContext(ctx, log.NullLogger{}), obj, sourceObj, &path)
			defer os.RemoveAll(path)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(obj.GetConditions()).ToNot(BeNil())
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.wantRevision != "" {
				g.Expect(path).ToNot(BeEmpty())
				g.Expect(path).To(BeARegularFile())
				chart, err := loader.Load(path)
				g.Expect(err).ToNot(HaveOccurred())

				g.Expect(chart.Metadata.Version).To(Equal(tt.wantRevision))
			}
		})
	}
}

func TestHelmChartReconciler_reconcileFromHelmRepository_secretRef(t *testing.T) {
	type options struct {
		username   string
		password   string
		publicKey  []byte
		privateKey []byte
		ca         []byte
	}

	tests := []struct {
		name             string
		server           options
		secret           *corev1.Secret
		beforeFunc       func(obj *sourcev1.HelmRepository)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "HTTP with BasicAuth",
			server: options{
				username: "username",
				password: "password",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "basic-auth",
				},
				Data: map[string][]byte{
					"username": []byte("username"),
					"password": []byte("password"),
				},
			},
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "basic-auth"}
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version 0.1.0"),
			},
		},
		{
			name: "HTTPS with CAFile",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tls",
				},
				Data: map[string][]byte{
					"certFile": tlsPublicKey,
					"keyFile":  tlsPrivateKey,
					"caFile":   tlsCA,
				},
			},
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "tls"}
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version 0.1.0"),
			},
		},
		{
			name: "HTTPS with invalid configuration",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "x509: certificate signed by unknown authority"),
			},
		},
		{
			name:   "Non-existing secret",
			secret: nil,
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret /non-existing: secrets \"non-existing\" not found"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server, err := helmtestserver.NewTempHelmServer()
			g.Expect(err).To(BeNil())
			defer g.Expect(os.RemoveAll(server.Root())).To(Succeed())

			g.Expect(server.PackageChart("testdata/charts/helmchart")).To(Succeed())
			g.Expect(server.GenerateIndex()).To(Succeed())

			if len(tt.server.username)+len(tt.server.password) > 0 {
				server.WithMiddleware(func(handler http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						u, p, ok := r.BasicAuth()
						if !ok || tt.server.username != u || tt.server.password != p {
							w.WriteHeader(401)
							return
						}
						handler.ServeHTTP(w, r)
					})
				})
			}

			if len(tt.server.publicKey)+len(tt.server.privateKey)+len(tt.server.ca) > 0 {
				g.Expect(server.StartTLS(tt.server.publicKey, tt.server.privateKey, tt.server.ca, "example.com")).To(Succeed())
			} else {
				server.Start()
			}
			defer server.Stop()

			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "helmrepository",
				},
				Spec: sourcev1.HelmRepositorySpec{
					Timeout: &metav1.Duration{Duration: timeout},
					URL:     server.URL(),
				},
				Status: sourcev1.HelmRepositoryStatus{
					Artifact: &sourcev1.Artifact{
						Path: "/helmrepository/secret-ref/index.yaml",
					},
				},
			}

			g.Expect(storage.MkdirAll(*repository.GetArtifact())).To(Succeed())
			defer storage.RemoveAll(*repository.GetArtifact())
			g.Expect(storage.CopyFromPath(repository.GetArtifact(), filepath.Join(server.Root(), "index.yaml"))).To(Succeed())

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name: "helmchart",
				},
				Spec: sourcev1.HelmChartSpec{
					Interval: metav1.Duration{Duration: interval},
					Chart:    "helmchart",
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(repository)
			}

			s := runtime.NewScheme()
			utilruntime.Must(corev1.AddToScheme(s))

			builder := fakeclient.NewClientBuilder().WithScheme(s)
			secret := tt.secret.DeepCopy()
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			r := &HelmChartReconciler{
				Client:  builder.Build(),
				Storage: storage,
				Getters: testGetters,
			}

			var path string
			got, err := r.reconcileFromHelmRepository(logr.NewContext(ctx, log.NullLogger{}), obj, repository, &path)
			defer os.RemoveAll(path)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(obj.GetConditions()).ToNot(BeNil())
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_reconcileFromTarballArtifact(t *testing.T) {
	tests := []struct {
		name             string
		artifact         sourcev1.Artifact
		beforeFunc       func(artifact *sourcev1.Artifact)
		afterFunc        func(artifact *sourcev1.Artifact)
		want             ctrl.Result
		wantErr          bool
		wantPath         bool
		wantRevision     string
		assertConditions []metav1.Condition
	}{
		{
			name: "Reconcile",
			artifact: sourcev1.Artifact{
				Revision: "checksum",
				Path:     "/fake/archive.tar.gz",
			},
			beforeFunc: func(artifact *sourcev1.Artifact) {
				storage.MkdirAll(*artifact)
				storage.Archive(artifact, "testdata/charts", nil)
			},
			afterFunc: func(artifact *sourcev1.Artifact) {
				os.RemoveAll(storage.LocalPath(*artifact))
			},
			want:     ctrl.Result{RequeueAfter: interval},
			wantPath: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Decompressed artifact checksum"),
			},
		},
		{
			name: "Non-existing artifact path",
			artifact: sourcev1.Artifact{
				Path: "/some/invalid/path",
			},
			wantErr:  true,
			wantPath: false,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Could not open artifact"),
			},
		},
		{
			name: "Invalid artifact file type",
			artifact: sourcev1.Artifact{
				Path: "/invalid/file.txt",
			},
			beforeFunc: func(artifact *sourcev1.Artifact) {
				storage.MkdirAll(*artifact)
				storage.AtomicWriteFile(artifact, bytes.NewReader([]byte("invalid")), 0655)
			},
			afterFunc: func(artifact *sourcev1.Artifact) {
				os.RemoveAll(storage.LocalPath(*artifact))
			},
			wantErr:  true,
			wantPath: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Decompression of artifact failed: requires gzip-compressed body: unexpected EOF"),
			},
		},
	}

	s := runtime.NewScheme()
	utilruntime.Must(sourcev1.AddToScheme(s))

	builder := fakeclient.NewClientBuilder().WithScheme(s)

	r := &HelmChartReconciler{
		Client:  builder.Build(),
		Storage: storage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name: "from-artifact-",
				},
				Spec: sourcev1.HelmChartSpec{
					Interval: metav1.Duration{Duration: interval},
					Chart:    "./helmchart",
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.artifact.DeepCopy())
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.artifact.DeepCopy())
			}

			var path string
			got, err := r.reconcileFromTarballArtifact(logr.NewContext(ctx, log.NullLogger{}), obj, tt.artifact, &path)
			defer os.RemoveAll(path)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(path != "").To(Equal(tt.wantPath))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(obj.GetConditions()).ToNot(BeNil())
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestHelmChartReconciler_getSource(t *testing.T) {
	helmRepo := &sourcev1.HelmRepository{
		TypeMeta: metav1.TypeMeta{
			Kind:       sourcev1.HelmRepositoryKind,
			APIVersion: sourcev1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "helmrepository",
		},
	}
	gitRepo := &sourcev1.GitRepository{
		TypeMeta: metav1.TypeMeta{
			Kind:       sourcev1.GitRepositoryKind,
			APIVersion: sourcev1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "gitrepository",
		},
	}
	bucket := &sourcev1.Bucket{
		TypeMeta: metav1.TypeMeta{
			Kind:       sourcev1.BucketKind,
			APIVersion: sourcev1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "bucket",
		},
	}

	tests := []struct {
		name      string
		sourceRef sourcev1.LocalHelmChartSourceReference
		want      sourcev1.Source
		wantErr   error
	}{
		{
			name: "HelmRepository",
			sourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.HelmRepositoryKind,
				Name: helmRepo.Name,
			},
			want: helmRepo,
		},
		{
			name: "GitRepository",
			sourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.GitRepositoryKind,
				Name: gitRepo.Name,
			},
			want: gitRepo,
		},
		{
			name: "Bucket",
			sourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.BucketKind,
				Name: bucket.Name,
			},
			want: bucket,
		},
		{
			name: "Unsupported",
			sourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.HelmChartKind,
			},
			want: nil,
			wantErr: unsupportedSourceKindError{
				Kind:      sourcev1.HelmChartKind,
				Supported: []string{sourcev1.HelmRepositoryKind, sourcev1.GitRepositoryKind, sourcev1.BucketKind},
			},
		},
	}

	s := runtime.NewScheme()
	utilruntime.Must(sourcev1.AddToScheme(s))

	builder := fakeclient.NewClientBuilder().WithScheme(s)
	builder.WithObjects(helmRepo, gitRepo, bucket)

	r := &HelmChartReconciler{
		Client:  builder.Build(),
		Storage: storage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name: "helmchart",
				},
				Spec: sourcev1.HelmChartSpec{
					SourceRef: tt.sourceRef,
				},
			}
			got, err := r.getSource(logr.NewContext(ctx, log.NullLogger{}), obj)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("getSource() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSource() got = %v, want %v", got, tt.want)
			}
		})
	}
}
