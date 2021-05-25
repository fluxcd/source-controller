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
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

const (
	bucketInterval = 1 * time.Second
	bucketTimeout  = 30 * time.Second
)

func TestBucketReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	s3Server := newS3Server("test-bucket")
	s3Server.Objects = []*s3MockObject{
		{
			Key:          "test.txt",
			Content:      []byte("test"),
			ContentType:  "text/plain",
			LastModified: time.Now(),
		},
	}
	s3Server.Start()
	defer s3Server.Stop()

	g.Expect(s3Server.GetURL()).ToNot(BeEmpty())
	u, err := url.Parse(s3Server.GetURL())
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
	g.Expect(newTestEnv.Create(ctx, secret)).To(Succeed())
	defer newTestEnv.Delete(ctx, secret)

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
			Interval:   metav1.Duration{Duration: bucketInterval},
			Timeout:    &metav1.Duration{Duration: bucketTimeout},
			SecretRef: &meta.LocalObjectReference{
				Name: secret.Name,
			},
		},
	}
	g.Expect(newTestEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for Bucket to be Ready
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}

		if !conditions.Has(obj, sourcev1.ArtifactAvailableCondition) ||
			!conditions.Has(obj, sourcev1.SourceAvailableCondition) ||
			!conditions.Has(obj, meta.ReadyCondition) ||
			obj.Status.Artifact == nil {
			return false
		}

		readyCondition := conditions.Get(obj, meta.ReadyCondition)

		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration
	}, timeout).Should(BeTrue())

	g.Expect(newTestEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for Bucket to be deleted
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestBucketReconciler_checksum(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(root string)
		want       string
		wantErr    bool
	}{
		{
			name: "empty root",
			want: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			name: "with file",
			beforeFunc: func(root string) {
				mockFile(root, "a/b/c.txt", "a dummy string")
			},
			want: "309a5e6e96b4a7eea0d1cfaabf1be8ec1c063fa0",
		},
		{
			name: "with file in different path",
			beforeFunc: func(root string) {
				mockFile(root, "a/b.txt", "a dummy string")
			},
			want: "e28c62b5cc488849950c4355dddc5523712616d4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := ioutil.TempDir("", "bucket-checksum-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			if tt.beforeFunc != nil {
				tt.beforeFunc(root)
			}
			got, err := (&BucketReconciler{}).checksum(root)
			if (err != nil) != tt.wantErr {
				t.Errorf("checksum() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("checksum() got = %v, want %v", got, tt.want)
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
	if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
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
