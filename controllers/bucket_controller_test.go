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
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

var _ = Describe("BucketReconciler", func() {

	const (
		timeout       = time.Second * 30
		interval      = time.Second * 1
		indexInterval = time.Second * 1
		bucketTimeout = time.Second * 5
	)

	var (
		namespace *corev1.Namespace
		s3Server  *s3MockServer
		err       error
	)

	BeforeEach(func() {
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "bucket-test-" + randStringRunes(5)},
		}
		err = k8sClient.Create(ctx, namespace)
		Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

		s3Server = newS3Server("test-bucket")
		s3Server.Objects = []*s3MockObject{
			{
				Key:          "test.txt",
				Content:      []byte("test"),
				ContentType:  "text/plain",
				LastModified: time.Now(),
			},
		}
		s3Server.Start()
	})

	AfterEach(func() {
		s3Server.Stop()

		err = k8sClient.Delete(ctx, namespace)
		Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
	})

	It("Creates artifacts for", func() {
		u, err := url.Parse(s3Server.GetURL())
		Expect(err).NotTo(HaveOccurred())

		key := types.NamespacedName{
			Name:      "bucket-test-" + randStringRunes(5),
			Namespace: namespace.Name,
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
			},
			Data: map[string][]byte{
				"accesskey": []byte("key"),
				"secretkey": []byte("secret"),
			},
		}

		Expect(k8sClient.Create(ctx, secret)).Should(Succeed())
		defer k8sClient.Delete(ctx, secret)

		bucket := &sourcev1.Bucket{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
			},
			Spec: sourcev1.BucketSpec{
				Provider:   "aws",
				BucketName: s3Server.BucketName,
				Endpoint:   u.Host,
				Insecure:   true,
				Interval:   metav1.Duration{Duration: indexInterval},
				Timeout:    &metav1.Duration{Duration: bucketTimeout},
				SecretRef: &corev1.LocalObjectReference{
					Name: secret.Name,
				},
			},
		}

		Expect(k8sClient.Create(ctx, bucket)).Should(Succeed())
		defer k8sClient.Delete(ctx, bucket)

		By("Expecting artifact")
		Eventually(func() bool {
			if err := k8sClient.Get(ctx, key, bucket); err != nil {
				return false
			}
			return bucket.Status.Artifact != nil &&
				storage.ArtifactExist(*bucket.Status.Artifact)
		}, timeout, interval).Should(BeTrue())

		By("Expecting finalizers to be registered")
		Expect(len(bucket.Finalizers) > 0).To(BeTrue())

		By("Updating the bucket files")
		s3Server.Objects = append(s3Server.Objects, &s3MockObject{
			Key:          "new.txt",
			Content:      []byte("new"),
			ContentType:  "text/plain",
			LastModified: time.Now(),
		})

		By("Expecting checksum change and GC")
		Eventually(func() bool {
			now := &sourcev1.Bucket{}
			if err := k8sClient.Get(ctx, key, now); err != nil {
				return false
			}
			// Test revision change and garbage collection
			return now.Status.Artifact.Checksum != bucket.Status.Artifact.Checksum &&
				!storage.ArtifactExist(*bucket.Status.Artifact)
		}, timeout, interval).Should(BeTrue())

		updated := &sourcev1.Bucket{}
		Expect(k8sClient.Get(ctx, key, updated)).Should(Succeed())
		updated.Spec.BucketName = "invalid#bucket?"
		Expect(k8sClient.Update(ctx, updated)).Should(Succeed())
		Eventually(func() bool {
			if err := k8sClient.Get(ctx, key, updated); err != nil {
				return false
			}
			for _, c := range updated.Status.Conditions {
				if c.Reason == sourcev1.BucketOperationFailedReason {
					return true
				}
			}
			return false
		}, timeout, interval).Should(BeTrue())
		Expect(updated.Status.Artifact).ToNot(BeNil())

		By("Expecting to delete successfully")
		Eventually(func() error {
			_ = k8sClient.Get(ctx, key, bucket)
			return k8sClient.Delete(ctx, bucket)
		}, timeout, interval).Should(Succeed())

		By("Expecting delete to finish")
		Eventually(func() error {
			return k8sClient.Get(ctx, key, bucket)
		}, timeout, interval).ShouldNot(Succeed())

		exists := func(path string) bool {
			// wait for tmp sync on macOS
			if runtime.GOOS == "darwin" {
				time.Sleep(time.Second)
			}

			_, err := os.Stat(path)
			return err == nil
		}

		By("Expecting GC after delete")
		Eventually(exists(bucket.Status.Artifact.Path), timeout, interval).ShouldNot(BeTrue())
	})
})

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

func (s *s3MockServer) GetURL() string {
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
			etag := md5.Sum([]byte(o.Content))
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

		etag := md5.Sum([]byte(found.Content))
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
