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

package controllers

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

func TestBucketReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	s3Server := newS3Server("test-bucket")
	s3Server.Objects = []*s3MockObject{
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

	obj := &sourcev1.Bucket{
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

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for Bucket to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestBucketReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.Bucket, storage *Storage) error
		want             ctrl.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.Bucket, storage *Storage) error {
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
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.Bucket, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/invalid.txt"),
					Revision: "d",
				}
				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: ctrl.Result{Requeue: true},
			assertPaths: []string{
				"!/reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactUnavailableCondition, "NoArtifact", "No artifact for resource in storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.Bucket, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/hostname.txt"),
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

			r := &BucketReconciler{
				Storage: testStorage,
			}

			obj := &sourcev1.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
			}
			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			got, err := r.reconcileStorage(context.TODO(), obj)
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

func TestBucketReconciler_reconcileMinioSource(t *testing.T) {
	tests := []struct {
		name             string
		bucketName       string
		bucketObjects    []*s3MockObject
		middleware       http.Handler
		secret           *corev1.Secret
		beforeFunc       func(obj *sourcev1.Bucket)
		want             ctrl.Result
		wantErr          bool
		assertArtifact   sourcev1.Artifact
		assertConditions []metav1.Condition
	}{
		{
			name:       "reconciles source",
			bucketName: "dummy",
			bucketObjects: []*s3MockObject{
				{
					Key:          "test.txt",
					Content:      []byte("test"),
					ContentType:  "text/plain",
					LastModified: time.Now(),
				},
			},
			assertArtifact: sourcev1.Artifact{
				Path:     "bucket/test-bucket/f0467900d3cede8323f3e61a1467f7cd370d1c0d942ff990a1a7be1eb1a231e8.tar.gz",
				Revision: "f0467900d3cede8323f3e61a1467f7cd370d1c0d942ff990a1a7be1eb1a231e8",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'f0467900d3cede8323f3e61a1467f7cd370d1c0d942ff990a1a7be1eb1a231e8'"),
			},
		},
		// TODO(hidde): middleware for mock server
		//{
		//	name: "authenticates using secretRef",
		//	bucketName: "dummy",
		//},
		{
			name:       "observes non-existing secretRef",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "dummy",
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret '/dummy': secrets \"dummy\" not found"),
			},
		},
		{
			name:       "observes invalid secretRef",
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
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "Failed to construct S3 client: invalid 'dummy' secret data: required fields"),
			},
		},
		{
			name:       "observes non-existing bucket name",
			bucketName: "dummy",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.BucketName = "invalid"
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "Bucket 'invalid' does not exist"),
			},
		},
		{
			name: "transient bucket name API failure",
			beforeFunc: func(obj *sourcev1.Bucket) {
				obj.Spec.Endpoint = "transient.example.com"
				obj.Spec.BucketName = "unavailable"
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason, "Failed to verify existence of bucket 'unavailable'"),
			},
		},
		{
			// TODO(hidde): test the lesser happy paths
			name:       ".sourceignore",
			bucketName: "dummy",
			bucketObjects: []*s3MockObject{
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
			assertArtifact: sourcev1.Artifact{
				Path:     "bucket/test-bucket/94992ae8fb8300723e970e304ea3414266cb414e364ba3f570bb09069f883100.tar.gz",
				Revision: "94992ae8fb8300723e970e304ea3414266cb414e364ba3f570bb09069f883100",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision '94992ae8fb8300723e970e304ea3414266cb414e364ba3f570bb09069f883100'"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.Scheme())
			if tt.secret != nil {
				builder.WithObjects(tt.secret)
			}
			r := &BucketReconciler{
				Client:  builder.Build(),
				Storage: testStorage,
			}
			tmpDir, err := os.MkdirTemp("", "reconcile-bucket-source-")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			obj := &sourcev1.Bucket{
				TypeMeta: metav1.TypeMeta{
					Kind: sourcev1.BucketKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bucket",
				},
				Spec: sourcev1.BucketSpec{
					Timeout: &metav1.Duration{Duration: timeout},
				},
			}

			var server *s3MockServer
			if tt.bucketName != "" {
				server = newS3Server(tt.bucketName)
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

			artifact := &sourcev1.Artifact{}
			got, err := r.reconcileSource(context.TODO(), obj, artifact, tmpDir)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(artifact).To(MatchArtifact(tt.assertArtifact.DeepCopy()))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestBucketReconciler_reconcileArtifact(t *testing.T) {
	// testChecksum is the checksum value of the artifacts created in this
	// test.
	const testChecksum = "4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1"

	tests := []struct {
		name             string
		beforeFunc       func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string)
		afterFunc        func(t *WithT, obj *sourcev1.Bucket, dir string)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archiving artifact to storage makes Ready=True",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Up-to-date artifact should not update status",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Status.Artifact = artifact.DeepCopy()
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				t.Expect(obj.Status.URL).To(BeEmpty())
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Removes ArtifactUnavailableCondition after creating artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactUnavailableCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Removes ArtifactOutdatedCondition after creating a new artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Creates latest symlink to the created artifact",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				symlinkPath := filepath.Join(filepath.Dir(localPath), "latest.tar.gz")
				targetFile, err := os.Readlink(symlinkPath)
				t.Expect(err).NotTo(HaveOccurred())
				t.Expect(localPath).To(Equal(targetFile))
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'existing'"),
			},
		},
		{
			name: "Dir path deleted",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
			},
			wantErr: true,
		},
		{
			name: "Dir path is not a directory",
			beforeFunc: func(t *WithT, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) {
				// Remove the given directory and create a file for the same
				// path.
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
				f, err := os.Create(dir)
				defer f.Close()
				t.Expect(err).ToNot(HaveOccurred())
			},
			afterFunc: func(t *WithT, obj *sourcev1.Bucket, dir string) {
				t.Expect(os.RemoveAll(dir)).ToNot(HaveOccurred())
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &BucketReconciler{
				Storage: testStorage,
			}

			tmpDir, err := os.MkdirTemp("", "reconcile-bucket-artifact-")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			obj := &sourcev1.Bucket{
				TypeMeta: metav1.TypeMeta{
					Kind: sourcev1.BucketKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-bucket-",
					Generation:   1,
					Namespace:    "default",
				},
				Spec: sourcev1.BucketSpec{
					Timeout: &metav1.Duration{Duration: timeout},
				},
			}

			artifact := testStorage.NewArtifactFor(obj.Kind, obj, "existing", "foo.tar.gz")
			artifact.Checksum = testChecksum

			if tt.beforeFunc != nil {
				tt.beforeFunc(g, obj, artifact, tmpDir)
			}

			got, err := r.reconcileArtifact(logr.NewContext(ctx, log.NullLogger{}), obj, artifact, tmpDir)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			// On error, artifact is empty. Check artifacts only on successful
			// reconcile.
			if !tt.wantErr {
				g.Expect(obj.Status.Artifact).To(MatchArtifact(artifact.DeepCopy()))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, tmpDir)
			}
		})
	}
}

func Test_etagIndex_Revision(t *testing.T) {
	tests := []struct {
		name    string
		list    etagIndex
		want    string
		wantErr bool
	}{
		{
			name: "index with items",
			list: map[string]string{
				"one":   "one",
				"two":   "two",
				"three": "three",
			},
			want: "8afaa9c32d7c187e8acaeffe899226011001f67c095519cdd8b4c03487c5b8bc",
		},
		{
			name: "index with items in different order",
			list: map[string]string{
				"three": "three",
				"one":   "one",
				"two":   "two",
			},
			want: "8afaa9c32d7c187e8acaeffe899226011001f67c095519cdd8b4c03487c5b8bc",
		},
		{
			name: "empty index",
			list: map[string]string{},
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "nil index",
			list: nil,
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.list.Revision()
			if (err != nil) != tt.wantErr {
				t.Errorf("revision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("revision() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// helpers

func mockFile(root, path, content string) error {
	filePath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		panic(err)
	}
	return nil
}

type s3MockObject struct {
	Key          string
	LastModified time.Time
	ContentType  string
	Content      []byte
}

type s3MockServer struct {
	srv *httptest.Server
	mux *http.ServeMux

	BucketName string
	Objects    []*s3MockObject
}

func newS3Server(bucketName string) *s3MockServer {
	s := &s3MockServer{BucketName: bucketName}
	s.mux = http.NewServeMux()
	s.mux.Handle(fmt.Sprintf("/%s/", s.BucketName), http.HandlerFunc(s.handler))

	s.srv = httptest.NewUnstartedServer(s.mux)

	return s
}

func (s *s3MockServer) Start() {
	s.srv.Start()
}

func (s *s3MockServer) Stop() {
	s.srv.Close()
}

func (s *s3MockServer) HTTPAddress() string {
	return s.srv.URL
}

func (s *s3MockServer) handler(w http.ResponseWriter, r *http.Request) {
	key := path.Base(r.URL.Path)

	switch key {
	case s.BucketName:
		w.Header().Add("Content-Type", "application/xml")

		if r.Method == http.MethodHead {
			return
		}

		q := r.URL.Query()

		if q["location"] != nil {
			fmt.Fprint(w, `
<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">Europe</LocationConstraint>
			`)
			return
		}

		contents := ""
		for _, o := range s.Objects {
			etag := md5.Sum(o.Content)
			contents += fmt.Sprintf(`
		<Contents>
			<Key>%s</Key>
			<LastModified>%s</LastModified>
			<Size>%d</Size>
			<ETag>&quot;%b&quot;</ETag>
			<StorageClass>STANDARD</StorageClass>
		</Contents>`, o.Key, o.LastModified.UTC().Format(time.RFC3339), len(o.Content), etag)
		}

		fmt.Fprintf(w, `
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	<Name>%s</Name>
	<Prefix/>
	<Marker/>
	<KeyCount>%d</KeyCount>
	<MaxKeys>1000</MaxKeys>
	<IsTruncated>false</IsTruncated>
	%s
</ListBucketResult>
		`, s.BucketName, len(s.Objects), contents)
	default:
		key, err := filepath.Rel("/"+s.BucketName, r.URL.Path)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		var found *s3MockObject
		for _, o := range s.Objects {
			if key == o.Key {
				found = o
			}
		}
		if found == nil {
			w.WriteHeader(404)
			return
		}

		etag := md5.Sum(found.Content)
		lastModified := strings.Replace(found.LastModified.UTC().Format(time.RFC1123), "UTC", "GMT", 1)

		w.Header().Add("Content-Type", found.ContentType)
		w.Header().Add("Last-Modified", lastModified)
		w.Header().Add("ETag", fmt.Sprintf("\"%b\"", etag))
		w.Header().Add("Content-Length", fmt.Sprintf("%d", len(found.Content)))

		if r.Method == http.MethodHead {
			return
		}

		w.Write(found.Content)
	}
}
