/*
Copyright 2022 The Flux authors

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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	"github.com/werf/nelm-source-controller/internal/index"
)

type mockBucketObject struct {
	etag string
	data string
}

type mockBucketClient struct {
	bucketName string
	objects    map[string]mockBucketObject
}

var errMockNotFound = fmt.Errorf("not found")

func (m mockBucketClient) BucketExists(_ context.Context, name string) (bool, error) {
	return name == m.bucketName, nil
}

func (m mockBucketClient) FGetObject(_ context.Context, bucket, obj, path string) (string, error) {
	if bucket != m.bucketName {
		return "", fmt.Errorf("bucket does not exist")
	}
	// tiny bit of protocol, for convenience: if asked for an object "error", then return an error.
	if obj == "error" {
		return "", fmt.Errorf("I was asked to report an error")
	}
	object, ok := m.objects[obj]
	if !ok {
		return "", errMockNotFound
	}
	if err := os.WriteFile(path, []byte(object.data), os.FileMode(0660)); err != nil {
		return "", err
	}
	return object.etag, nil
}

func (m mockBucketClient) ObjectIsNotFound(e error) bool {
	return e == errMockNotFound
}

func (m mockBucketClient) VisitObjects(_ context.Context, _ string, _ string, f func(key, etag string) error) error {
	for key, obj := range m.objects {
		if err := f(key, obj.etag); err != nil {
			return err
		}
	}
	return nil
}

func (m mockBucketClient) Close(_ context.Context) {}

func (m *mockBucketClient) addObject(key string, object mockBucketObject) {
	if m.objects == nil {
		m.objects = make(map[string]mockBucketObject)
	}
	m.objects[key] = object
}

func (m *mockBucketClient) objectsToDigestIndex() *index.Digester {
	i := index.NewDigester()
	for k, v := range m.objects {
		i.Add(k, v.etag)
	}
	return i
}

func Test_fetchEtagIndex(t *testing.T) {
	bucketName := "all-my-config"

	bucket := sourcev1.Bucket{
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Timeout:    &metav1.Duration{Duration: 1 * time.Hour},
		},
	}

	t.Run("fetches etag index", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject("foo.yaml", mockBucketObject{data: "foo.yaml", etag: "etag1"})
		client.addObject("bar.yaml", mockBucketObject{data: "bar.yaml", etag: "etag2"})
		client.addObject("baz.yaml", mockBucketObject{data: "baz.yaml", etag: "etag3"})

		index := index.NewDigester()
		err := fetchEtagIndex(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}

		g := NewWithT(t)
		g.Expect(index.Len()).To(Equal(3))
	})

	t.Run("an error while bucket does not exist", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: "other-bucket-name"}

		index := index.NewDigester()
		err := fetchEtagIndex(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		g := NewWithT(t)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("not found"))
	})

	t.Run("filters with .sourceignore rules", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject(".sourceignore", mockBucketObject{etag: "sourceignore1", data: `*.txt`})
		client.addObject("foo.yaml", mockBucketObject{etag: "etag1", data: "foo.yaml"})
		client.addObject("foo.txt", mockBucketObject{etag: "etag2", data: "foo.txt"})

		index := index.NewDigester()
		err := fetchEtagIndex(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(filepath.Join(tmp, ".sourceignore")); err != nil {
			t.Error(err)
		}

		if ok := index.Has("foo.txt"); ok {
			t.Error(fmt.Errorf("expected 'foo.txt' index item to not exist"))
		}
		g := NewWithT(t)
		g.Expect(index.Len()).To(Equal(1))
	})

	t.Run("filters with ignore rules from object", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject(".sourceignore", mockBucketObject{etag: "sourceignore1", data: `*.txt`})
		client.addObject("foo.txt", mockBucketObject{etag: "etag1", data: "foo.txt"})

		ignore := "!*.txt"
		bucket := bucket.DeepCopy()
		bucket.Spec.Ignore = &ignore

		index := index.NewDigester()
		err := fetchEtagIndex(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(filepath.Join(tmp, ".sourceignore")); err != nil {
			t.Error(err)
		}

		g := NewWithT(t)
		g.Expect(index.Len()).To(Equal(1))
		if ok := index.Has("foo.txt"); !ok {
			t.Error(fmt.Errorf("expected 'foo.txt' index item to exist"))
		}
	})
}

func Test_fetchFiles(t *testing.T) {
	bucketName := "all-my-config"

	bucket := sourcev1.Bucket{
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Timeout:    &metav1.Duration{Duration: 1 * time.Hour},
		},
	}

	t.Run("fetches files", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject("foo.yaml", mockBucketObject{data: "foo.yaml", etag: "etag1"})
		client.addObject("bar.yaml", mockBucketObject{data: "bar.yaml", etag: "etag2"})
		client.addObject("baz.yaml", mockBucketObject{data: "baz.yaml", etag: "etag3"})

		index := client.objectsToDigestIndex()

		err := fetchIndexFiles(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}

		for path := range index.Index() {
			p := filepath.Join(tmp, path)
			_, err := os.Stat(p)
			if err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("an error while fetching returns an error for the whole procedure", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName, objects: map[string]mockBucketObject{}}
		client.objects["error"] = mockBucketObject{}

		err := fetchIndexFiles(context.TODO(), client, bucket.DeepCopy(), client.objectsToDigestIndex(), tmp)
		if err == nil {
			t.Fatal("expected error but got nil")
		}
	})

	t.Run("a changed etag updates the index", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject("foo.yaml", mockBucketObject{data: "foo.yaml", etag: "etag2"})

		index := index.NewDigester()
		index.Add("foo.yaml", "etag1")
		err := fetchIndexFiles(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}
		f := index.Get("foo.yaml")
		g := NewWithT(t)
		g.Expect(f).To(Equal("etag2"))
	})

	t.Run("a disappeared index entry is removed from the index", func(t *testing.T) {
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		client.addObject("foo.yaml", mockBucketObject{data: "foo.yaml", etag: "etag1"})

		index := index.NewDigester()
		index.Add("foo.yaml", "etag1")
		// Does not exist on server
		index.Add("bar.yaml", "etag2")

		err := fetchIndexFiles(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}
		f := index.Get("foo.yaml")
		g := NewWithT(t)
		g.Expect(f).To(Equal("etag1"))
		g.Expect(index.Has("bar.yaml")).To(BeFalse())
	})

	t.Run("can fetch more than maxConcurrentFetches", func(t *testing.T) {
		// this will fail if, for example, the semaphore is not used correctly and blocks
		tmp := t.TempDir()

		client := mockBucketClient{bucketName: bucketName}
		for i := 0; i < 2*maxConcurrentBucketFetches; i++ {
			f := fmt.Sprintf("file-%d", i)
			client.addObject(f, mockBucketObject{etag: f, data: f})
		}
		index := client.objectsToDigestIndex()

		err := fetchIndexFiles(context.TODO(), client, bucket.DeepCopy(), index, tmp)
		if err != nil {
			t.Fatal(err)
		}
	})
}
