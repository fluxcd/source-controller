/*
Copyright 2021 The Flux authors

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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	kstatus "github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/pkg/apis/meta"
	intdigest "github.com/fluxcd/pkg/artifact/digest"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	"github.com/werf/nelm-source-controller/internal/index"
	gcsmock "github.com/werf/nelm-source-controller/internal/mock/gcs"
	s3mock "github.com/werf/nelm-source-controller/internal/mock/s3"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
)

// Environment variable to set the GCP Storage host for the GCP client.
const EnvGcpStorageHost = "STORAGE_EMULATOR_HOST"

func TestBucketReconciler_deleteBeforeFinalizer(t *testing.T) {
	g := NewWithT(t)

	namespaceName := "bucket-" + randStringRunes(5)
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}
	g.Expect(k8sClient.Create(ctx, namespace)).ToNot(HaveOccurred())
	t.Cleanup(func() {
		g.Expect(k8sClient.Delete(ctx, namespace)).NotTo(HaveOccurred())
	})

	bucket := &sourcev1.Bucket{}
	bucket.Name = "test-bucket"
	bucket.Namespace = namespaceName
	bucket.Spec = sourcev1.BucketSpec{
		Interval:   metav1.Duration{Duration: interval},
		BucketName: "foo",
		Endpoint:   "bar",
	}
	// Add a test finalizer to prevent the object from getting deleted.
	bucket.SetFinalizers([]string{"test-finalizer"})
	g.Expect(k8sClient.Create(ctx, bucket)).NotTo(HaveOccurred())
	// Add deletion timestamp by deleting the object.
	g.Expect(k8sClient.Delete(ctx, bucket)).NotTo(HaveOccurred())

	r := &BucketReconciler{
		Client:        k8sClient,
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}
	// NOTE: Only a real API server responds with an error in this scenario.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	g.Expect(err).NotTo(HaveOccurred())
}

func TestBucketReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	s3Server := s3mock.NewServer("test-bucket")
	s3Server.Objects = []*s3mock.Object{
		{
			Key:          "test.yaml",
			Content:      []byte("test"),
			ContentType:  "text/plain",
			LastModified: time.Now(),
		},
	}
	s3Server.Start()
	defer s3Server.Stop()

	g.Expect(s3Server.HTTPAddress()).ToNot(BeEmpty())
	u, err := url.Parse(s3Server.HTTPAddress())
	g.Expect(err).NotTo(HaveOccurred())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "bucket-reconcile-",
			Namespace:    "default",
		},
		Data: map[string][]byte{
			"accesskey": []byte("key"),
			"secretkey": []byte("secret"),
		},
	}
	g.Expect(testEnv.Create(ctx, secret)).To(Succeed())
	defer testEnv.Delete(ctx, secret)

	origObj := &sourcev1.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "bucket-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.BucketSpec{
			Provider:   "generic",
			BucketName: s3Server.BucketName,
			Endpoint:   u.Host,
			Insecure:   true,
			Interval:   metav1.Duration{Duration: interval},
			Timeout:    &metav1.Duration{Duration: timeout},
			SecretRef: &meta.LocalObjectReference{
				Name: secret.Name,
			},
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

	// Wait for Bucket to be Ready
	waitForSourceReadyWithArtifact(ctx, g, obj)

	// Check if the object status is valid.
	condns := &conditionscheck.Conditions{NegativePolarity: bucketReadyCondition.NegativePolarity}
	checker := conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	// kstatus client conformance check.
	uo, err := patch.ToUnstructured(obj)
	g.Expect(err).ToNot(HaveOccurred())
	res, err := kstatus.Compute(uo)
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

	// Wait for Bucket to be deleted
	waitForSourceDeletion(ctx, g, obj)

	// Check if a suspended object gets deleted.
	obj = origObj.DeepCopy()
	testSuspendedObjectDeleteWithArtifact(ctx, g, obj)
}

func TestBucketReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.Bucket, storage *storage.Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *meta.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.Bucket, storage *storage.Storage) error {
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
			beforeFunc: func(obj *sourcev1.Bucket, storage *storage.Storage) error {
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
			beforeFunc: func(obj *sourcev1.Bucket, storage *storage.Storage) error {
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
			beforeFunc: func(obj *sourcev1.Bucket, storage *storage.Storage) error {
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
			beforeFunc: func(obj *sourcev1.Bucket, storage *storage.Storage) error {
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

			r := &BucketReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.Bucket{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(bucketReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.Bucket{
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

			index := index.NewDigester()
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileStorage(context.TODO(), sp, obj, index, "")
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

func TestBucketReconciler_reconcileSource_generic(t *testing.T) {
	tests := []struct {
		name             string
		bucketName       string
		bucketObjects    []*s3mock.Object
		middleware       http.Handler
		secret           *corev1.Secret
		serviceAccount   *corev1.ServiceAccount
		beforeFunc       func(obj *sourcev1.Bucket)
		want             sreconcile.Result
		wantErr          bool
		assertIndex      *index.Digester
		assertConditions []metav1.Condition
	}{
		{
			name:       "Reconciles generic source",
			bucketName: "dummy",
			bucketObjects: []*s3mock.Object{
				{
					Key:          "test.txt",
					Content:      []byte("test"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		// TODO(hidde): middleware for mock server
		//{
		//	name: "authenticates using secretRef",
		//	bucketName: "dummy",
		//},
		{
			name:       "Observes non-existing secretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret '/dummy': secrets \"dummy\" not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid secretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "invalid 'dummy' secret data: required fields 'accesskey' and 'secretkey'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes non-existing certSecretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get TLS config: secret '/dummy' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid certSecretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get TLS config: secret '/dummy' must contain either 'ca.crt' or both 'tls.crt' and 'tls.key'"),
			},
		},
		{
			name:       "Observes non-existing proxySecretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ProxySecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get proxy URL: secret '/dummy' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid proxySecretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
				Data: map[string][]byte{},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ProxySecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get proxy URL: secret '/dummy': key 'address' not found"),
			},
		},
		{
			name:       "Observes non-existing sts.secretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					SecretRef: &meta.LocalObjectReference{Name: "dummy"},
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get STS secret '/dummy': secrets \"dummy\" not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid sts.secretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Provider = "generic"
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					Provider:  "ldap",
					Endpoint:  "https://something",
					SecretRef: &meta.LocalObjectReference{Name: "dummy"},
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "invalid 'dummy' secret data for 'ldap' STS provider: required fields username, password"),
			},
		},
		{
			name:       "Observes non-existing sts.certSecretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					CertSecretRef: &meta.LocalObjectReference{Name: "dummy"},
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get STS TLS config: secret '/dummy' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid sts.certSecretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Provider = "generic"
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					Provider:      "ldap",
					Endpoint:      "https://something",
					CertSecretRef: &meta.LocalObjectReference{Name: "dummy"},
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get STS TLS config: secret '/dummy' must contain either 'ca.crt' or both 'tls.crt' and 'tls.key'"),
			},
		},
		{
			name:       "Observes non-existing bucket name",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.BucketName = "invalid"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "bucket 'invalid' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes incompatible sts.provider",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Provider = "generic"
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					Provider: "aws",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.InvalidSTSConfigurationReason, "STS provider 'aws' is not supported for 'generic' bucket provider"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid sts.endpoint",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Provider = "generic"
				obj.Spec.STS = &sourcev1.BucketSTSSpec{
					Provider: "ldap",
					Endpoint: "something\t",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "failed to parse STS endpoint 'something\t': parse \"something\\t\": net/url: invalid control character in URL"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Transient bucket name API failure",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Endpoint = "transient.example.com"
				obj.Spec.BucketName = "unavailable"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "failed to confirm existence of 'unavailable' bucket"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       ".sourceignore",
			bucketName: "dummy",
			bucketObjects: []*s3mock.Object{
				{
					Key:          ".sourceignore",
					Content:      []byte("ignored/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
				{
					Key:          "ignored/file.txt",
					Content:      []byte("ignored/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
				{
					Key:          "included/file.txt",
					Content:      []byte("included/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"included/file.txt": "5a4bc7048b3301f677fe15b8678be2f8",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:9fc2ddfc4a6f44e6c3efee40af36578b9e76d4d930eaf384b8435a0aa0bf7a0f'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:9fc2ddfc4a6f44e6c3efee40af36578b9e76d4d930eaf384b8435a0aa0bf7a0f'"),
			},
		},
		{
			name:       "spec.ignore overrides .sourceignore",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				ignore := "!ignored/file.txt"
				obj.Spec.Ignore = &ignore
			},
			bucketObjects: []*s3mock.Object{
				{
					Key:          ".sourceignore",
					Content:      []byte("ignored/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
				{
					Key:          "ignored/file.txt",
					Content:      []byte("ignored/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
				{
					Key:          "included/file.txt",
					Content:      []byte("included/file.txt"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"ignored/file.txt":  "f08907038338288420ae7dc2d30c0497",
				"included/file.txt": "5a4bc7048b3301f677fe15b8678be2f8",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:117f586dc64cfc559329e21d286edcbb94cb6b1581517eaddc0ab5292b470cd5'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:117f586dc64cfc559329e21d286edcbb94cb6b1581517eaddc0ab5292b470cd5'"),
			},
		},
		{
			name:       "Up-to-date artifact",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{
					Revision: "sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			bucketObjects: []*s3mock.Object{
				{
					Key:          "test.txt",
					Content:      []byte("test"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Removes FetchFailedCondition after reconciling source",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "failed to read test file")
			},
			bucketObjects: []*s3mock.Object{
				{
					Key:          "test.txt",
					Content:      []byte("test"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "Existing artifact makes ArtifactOutdated=True",
			bucketName: "dummy",
			bucketObjects: []*s3mock.Object{
				{
					Key:          "test.txt",
					Content:      []byte("test"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "some-path",
					Revision: "some-rev",
				}
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithStatusSubresource(&sourcev1.Bucket{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret)
			}

			if tt.serviceAccount != nil {
				clientBuilder.WithObjects(tt.serviceAccount)
			}

			r := &BucketReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        clientBuilder.Build(),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(bucketReadyCondition.Owned, "sc"),
			}
			tmpDir := t.TempDir()

			obj := &sourcev1.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
				},
				Spec: sourcev1.BucketSpec{
					Timeout: &metav1.Duration{Duration: timeout},
				},
			}

			var server *s3mock.Server
			if tt.bucketName != "" {
				server = s3mock.NewServer(tt.bucketName)
				server.Objects = tt.bucketObjects
				server.Start()
				defer server.Stop()

				g.Expect(server.HTTPAddress()).ToNot(BeEmpty())
				u, err := url.Parse(server.HTTPAddress())
				g.Expect(err).NotTo(HaveOccurred())

				obj.Spec.BucketName = tt.bucketName
				obj.Spec.Endpoint = u.Host
				// TODO(hidde): also test TLS
				obj.Spec.Insecure = true
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			index := index.NewDigester()
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(context.TODO(), sp, obj, index, tmpDir)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(index.Index()).To(Equal(tt.assertIndex.Index()))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestBucketReconciler_reconcileSource_gcs(t *testing.T) {
	tests := []struct {
		name                               string
		bucketName                         string
		bucketObjects                      []*gcsmock.Object
		secret                             *corev1.Secret
		serviceAccount                     *corev1.ServiceAccount
		beforeFunc                         func(obj *sourcev1.Bucket)
		want                               sreconcile.Result
		wantErr                            bool
		assertIndex                        *index.Digester
		assertConditions                   []metav1.Condition
		disableObjectLevelWorkloadIdentity bool
	}{
		{
			name:       "Reconciles GCS source",
			bucketName: "dummy",
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					ContentType: "text/plain",
					Content:     []byte("test"),
					Generation:  3,
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
				Data: map[string][]byte{
					"accesskey":      []byte("key"),
					"secretkey":      []byte("secret"),
					"serviceaccount": []byte("testsa"),
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "Observes non-existing secretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret '/dummy': secrets \"dummy\" not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid secretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "invalid 'dummy' secret data: required fields"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes non-existing proxySecretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ProxySecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get proxy URL: secret '/dummy' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes invalid proxySecretRef",
			bucketName: "dummy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dummy",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ProxySecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get proxy URL: secret '/dummy': key 'address' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Observes non-existing bucket name",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.BucketName = "invalid"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "bucket 'invalid' not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Transient bucket name API failure",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Endpoint = "transient.example.com"
				obj.Spec.BucketName = "unavailable"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "failed to confirm existence of 'unavailable' bucket"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       ".sourceignore",
			bucketName: "dummy",
			bucketObjects: []*gcsmock.Object{
				{
					Key:         ".sourceignore",
					Content:     []byte("ignored/file.txt"),
					ContentType: "text/plain",
					Generation:  1,
				},
				{
					Key:         "ignored/file.txt",
					Content:     []byte("ignored/file.txt"),
					ContentType: "text/plain",
					Generation:  4,
				},
				{
					Key:         "included/file.txt",
					Content:     []byte("included/file.txt"),
					ContentType: "text/plain",
					Generation:  3,
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"included/file.txt": "5a4bc7048b3301f677fe15b8678be2f8",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:9fc2ddfc4a6f44e6c3efee40af36578b9e76d4d930eaf384b8435a0aa0bf7a0f'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:9fc2ddfc4a6f44e6c3efee40af36578b9e76d4d930eaf384b8435a0aa0bf7a0f'"),
			},
		},
		{
			name:       "spec.ignore overrides .sourceignore",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				ignore := "!ignored/file.txt"
				obj.Spec.Ignore = &ignore
			},
			bucketObjects: []*gcsmock.Object{
				{
					Key:         ".sourceignore",
					Content:     []byte("ignored/file.txt"),
					ContentType: "text/plain",
					Generation:  1,
				},
				{
					Key:         "ignored/file.txt",
					Content:     []byte("ignored/file.txt"),
					ContentType: "text/plain",
					Generation:  2,
				},
				{
					Key:         "included/file.txt",
					Content:     []byte("included/file.txt"),
					ContentType: "text/plain",
					Generation:  4,
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"ignored/file.txt":  "f08907038338288420ae7dc2d30c0497",
				"included/file.txt": "5a4bc7048b3301f677fe15b8678be2f8",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:117f586dc64cfc559329e21d286edcbb94cb6b1581517eaddc0ab5292b470cd5'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:117f586dc64cfc559329e21d286edcbb94cb6b1581517eaddc0ab5292b470cd5'"),
			},
		},
		{
			name:       "Up-to-date artifact",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{
					Revision: "sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479",
				}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					Content:     []byte("test"),
					ContentType: "text/plain",
					Generation:  2,
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name:       "Removes FetchFailedCondition after reconciling source",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "failed to read test file")
			},
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					Content:     []byte("test"),
					ContentType: "text/plain",
					Generation:  2,
				},
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "Existing artifact makes ArtifactOutdated=True",
			bucketName: "dummy",
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					ContentType: "text/plain",
					Content:     []byte("test"),
					Generation:  3,
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "some-path",
					Revision: "some-rev",
				}
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "GCS Object-Level Workload Identity (no secret)",
			bucketName: "dummy",
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					ContentType: "text/plain",
					Content:     []byte("test"),
					Generation:  3,
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sa",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ServiceAccountName = "test-sa"
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "GCS Controller-Level Workload Identity (no secret, no SA)",
			bucketName: "dummy",
			bucketObjects: []*gcsmock.Object{
				{
					Key:         "test.txt",
					ContentType: "text/plain",
					Content:     []byte("test"),
					Generation:  3,
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				// ServiceAccountName は設定しない (Controller-Level)
			},
			want: sreconcile.ResultSuccess,
			assertIndex: index.NewDigester(index.WithIndex(map[string]string{
				"test.txt": "098f6bcd4621d373cade4e832627b4f6",
			})),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'sha256:b4c2a60ce44b67f5b659a95ce4e4cc9e2a86baf13afb72bd397c5384cbc0e479'"),
			},
		},
		{
			name:       "GCS Object-Level fails when feature gate disabled",
			bucketName: "dummy",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sa",
				},
			},
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.ServiceAccountName = "test-sa"
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:        sreconcile.ResultEmpty,
			wantErr:     true,
			assertIndex: index.NewDigester(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, meta.FeatureGateDisabledReason, "to use spec.serviceAccountName for provider authentication please enable the ObjectLevelWorkloadIdentity feature gate in the controller"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
			disableObjectLevelWorkloadIdentity: true,
		},
		// TODO: Middleware for mock server to test authentication using secret.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithStatusSubresource(&sourcev1.Bucket{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret)
			}

			if tt.serviceAccount != nil {
				clientBuilder.WithObjects(tt.serviceAccount)
			}

			r := &BucketReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        clientBuilder.Build(),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(bucketReadyCondition.Owned, "sc"),
			}

			// Handle ObjectLevelWorkloadIdentity feature gate
			if !tt.disableObjectLevelWorkloadIdentity {
				auth.EnableObjectLevelWorkloadIdentity()
				t.Cleanup(auth.DisableObjectLevelWorkloadIdentity)
			}

			tmpDir := t.TempDir()

			// Test bucket object.
			obj := &sourcev1.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
				},
				Spec: sourcev1.BucketSpec{
					BucketName: tt.bucketName,
					Timeout:    &metav1.Duration{Duration: timeout},
					Provider:   "gcp",
				},
			}

			// Set up the mock GCP bucket server.
			server := gcsmock.NewServer(tt.bucketName)
			server.Objects = tt.bucketObjects
			server.Start()
			defer server.Stop()

			g.Expect(server.HTTPAddress()).ToNot(BeEmpty())

			obj.Spec.Endpoint = server.HTTPAddress()
			obj.Spec.Insecure = true

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			// Set the GCP storage host to be used by the GCP client.
			g.Expect(os.Setenv(EnvGcpStorageHost, obj.Spec.Endpoint)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(os.Unsetenv(EnvGcpStorageHost)).ToNot(HaveOccurred())
			}()

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			index := index.NewDigester()
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(context.TODO(), sp, obj, index, tmpDir)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))

			g.Expect(index.Index()).To(Equal(tt.assertIndex.Index()))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestBucketReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string)
		afterFunc        func(t *WithT, obj *sourcev1.Bucket, dir string)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archiving artifact to storage makes ArtifactInStorage=True",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Up-to-date artifact should not persist and update status",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				revision := index.Digest(intdigest.Canonical)
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				// Incomplete artifact
				obj.Status.Artifact = &meta.Artifact{Revision: revision.String()}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				// Still incomplete
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Removes ArtifactOutdatedCondition after creating a new artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Creates latest symlink to the created artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "latest.tar.gz")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact: revision 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Dir path deleted",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.StatOperationFailedReason, "failed to stat source path"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "Dir path is not a directory",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, index *index.Digester, dir string) {
				// Remove the given directory and create a file for the same
				// path.
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
				f, err := os.Create(dir)
				t.Expect(err).ToNot(HaveOccurred())
				t.Expect(f.Close()).ToNot(HaveOccurred())
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, "foo", "bar")
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.InvalidPathReason, "is not a directory"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.Bucket{})

			r := &BucketReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(bucketReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
				},
				Spec: sourcev1.BucketSpec{
					Timeout: &metav1.Duration{Duration: timeout},
				},
			}

			tmpDir := t.TempDir()
			index := index.NewDigester()

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, index, tmpDir)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileArtifact(context.TODO(), sp, obj, index, tmpDir)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			// On error, artifact is empty. Check artifacts only on successful
			// reconcile.
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, tmpDir)
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestBucketReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.Bucket)
		assertConditions []metav1.Condition
		wantErr          bool
	}{
		{
			name: "positive conditions only",
			beforeFunc: func(obj *sourcev1.Bucket) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *sourcev1.Bucket) {
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
			wantErr: true,
		},
		{
			name: "mixed positive and negative conditions",
			beforeFunc: func(obj *sourcev1.Bucket) {
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

			obj := &sourcev1.Bucket{
				TypeMeta: metav1.TypeMeta{
					APIVersion: sourcev1.GroupVersion.String(),
					Kind:       sourcev1.BucketKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bucket",
					Namespace: "foo",
				},
			}

			c := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithObjects(obj).
				WithStatusSubresource(&sourcev1.Bucket{}).
				Build()

			serialPatcher := patch.NewSerialPatcher(obj, c)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), serialPatcher)
			summarizeOpts := []summarize.Option{
				summarize.WithConditions(bucketReadyCondition),
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

func TestBucketReconciler_notify(t *testing.T) {
	tests := []struct {
		name             string
		res              sreconcile.Result
		resErr           error
		oldObjBeforeFunc func(obj *sourcev1.Bucket)
		newObjBeforeFunc func(obj *sourcev1.Bucket)
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
			newObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
			},
			wantEvent: "Normal NewArtifact stored artifact with 2 fetched files from",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored artifact with 2 fetched files from",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored artifact with 2 fetched files from",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.Bucket) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.Bucket{
				Spec: sourcev1.BucketSpec{
					BucketName: "test-bucket",
				},
			}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &BucketReconciler{
				EventRecorder: recorder,
				patchOptions:  getPatchOptions(bucketReadyCondition.Owned, "sc"),
			}
			index := index.NewDigester(index.WithIndex(map[string]string{
				"zzz": "qqq",
				"bbb": "ddd",
			}))
			reconciler.notify(ctx, oldObj, newObj, index, tt.res, tt.resErr)

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

func TestBucketReconciler_APIServerValidation_STS(t *testing.T) {
	tests := []struct {
		name           string
		bucketProvider string
		stsConfig      *sourcev1.BucketSTSSpec
		err            string
	}{
		{
			name:           "gcp unsupported",
			bucketProvider: "gcp",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "aws",
				Endpoint: "http://test",
			},
			err: "STS configuration is only supported for the 'aws' and 'generic' Bucket providers",
		},
		{
			name:           "azure unsupported",
			bucketProvider: "azure",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "aws",
				Endpoint: "http://test",
			},
			err: "STS configuration is only supported for the 'aws' and 'generic' Bucket providers",
		},
		{
			name:           "aws supported",
			bucketProvider: "aws",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "aws",
				Endpoint: "http://test",
			},
		},
		{
			name:           "invalid endpoint",
			bucketProvider: "aws",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "aws",
				Endpoint: "test",
			},
			err: "spec.sts.endpoint in body should match '^(http|https)://.*$'",
		},
		{
			name:           "gcp can be created without STS config",
			bucketProvider: "gcp",
		},
		{
			name:           "azure can be created without STS config",
			bucketProvider: "azure",
		},
		{
			name:           "generic can be created without STS config",
			bucketProvider: "generic",
		},
		{
			name:           "aws can be created without STS config",
			bucketProvider: "aws",
		},
		{
			name:           "ldap unsupported for aws",
			bucketProvider: "aws",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: "http://test",
			},
			err: "'aws' is the only supported STS provider for the 'aws' Bucket provider",
		},
		{
			name:           "aws unsupported for generic",
			bucketProvider: "generic",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "aws",
				Endpoint: "http://test",
			},
			err: "'ldap' is the only supported STS provider for the 'generic' Bucket provider",
		},
		{
			name:           "aws does not require a secret",
			bucketProvider: "aws",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider:  "aws",
				Endpoint:  "http://test",
				SecretRef: &meta.LocalObjectReference{},
			},
			err: "spec.sts.secretRef is not required for the 'aws' STS provider",
		},
		{
			name:           "aws does not require a cert secret",
			bucketProvider: "aws",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider:      "aws",
				Endpoint:      "http://test",
				CertSecretRef: &meta.LocalObjectReference{},
			},
			err: "spec.sts.certSecretRef is not required for the 'aws' STS provider",
		},
		{
			name:           "ldap may use a secret",
			bucketProvider: "generic",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider:  "ldap",
				Endpoint:  "http://test",
				SecretRef: &meta.LocalObjectReference{},
			},
		},
		{
			name:           "ldap may use a cert secret",
			bucketProvider: "generic",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider:      "ldap",
				Endpoint:      "http://test",
				CertSecretRef: &meta.LocalObjectReference{},
			},
		},
		{
			name:           "ldap may not use a secret or cert secret",
			bucketProvider: "generic",
			stsConfig: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: "http://test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "bucket-reconcile-",
					Namespace:    "default",
				},
				Spec: sourcev1.BucketSpec{
					Provider:   tt.bucketProvider,
					BucketName: "test",
					Endpoint:   "test",
					Suspend:    true,
					Interval:   metav1.Duration{Duration: interval},
					Timeout:    &metav1.Duration{Duration: timeout},
					STS:        tt.stsConfig,
				},
			}

			err := testEnv.Create(ctx, obj)
			if err == nil {
				defer func() {
					err := testEnv.Delete(ctx, obj)
					g.Expect(err).NotTo(HaveOccurred())
				}()
			}

			if tt.err != "" {
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}
