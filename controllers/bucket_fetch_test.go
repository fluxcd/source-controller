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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

type mockBucketClient struct {
	bucketName string
	objects    map[string]string
}

var mockNotFound = fmt.Errorf("not found")

func (m mockBucketClient) BucketExists(c context.Context, name string) (bool, error) {
	return name == m.bucketName, nil
}

func (m mockBucketClient) ObjectExists(c context.Context, bucket, obj string) (bool, error) {
	if bucket != m.bucketName {
		return false, fmt.Errorf("bucket does not exist")
	}
	_, ok := m.objects[obj]
	return ok, nil
}

func (m mockBucketClient) FGetObject(c context.Context, bucket, obj, path string) error {
	if bucket != m.bucketName {
		return fmt.Errorf("bucket does not exist")
	}
	// tiny bit of protocol, for convenience: if asked for an object "error", then return an error.
	if obj == "error" {
		return fmt.Errorf("I was asked to report an error")
	}
	object, ok := m.objects[obj]
	if !ok {
		return mockNotFound
	}
	return os.WriteFile(path, []byte(object), os.FileMode(0660))
}

func (m mockBucketClient) ObjectIsNotFound(e error) bool {
	return e == mockNotFound
}

func (m mockBucketClient) VisitObjects(c context.Context, bucket string, f func(string) error) error {
	for path := range m.objects {
		if err := f(path); err != nil {
			return err
		}
	}
	return nil
}

func (m mockBucketClient) Close(c context.Context) {
	return
}

// Since the algorithm for fetching files uses concurrency and has some complications around error
// reporting, it's worth testing by itself.
func TestFetchFiles(t *testing.T) {
	files := map[string]string{
		"foo.yaml": "foo: 1",
		"bar.yaml": "bar: 2",
		"baz.yaml": "baz: 3",
	}
	bucketName := "all-my-config"

	bucket := sourcev1.Bucket{
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Timeout:    &metav1.Duration{Duration: 1 * time.Hour},
		},
	}
	client := mockBucketClient{
		objects:    files,
		bucketName: bucketName,
	}

	t.Run("fetch files happy path", func(t *testing.T) {
		tmp, err := os.MkdirTemp("", "test-bucket")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		_, err = fetchFiles(context.TODO(), client, bucket, tmp)
		if err != nil {
			t.Fatal(err)
		}

		for path := range files {
			p := filepath.Join(tmp, path)
			_, err := os.Stat(p)
			if err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("an error while fetching returns an error for the whole procedure", func(t *testing.T) {
		tmp, err := os.MkdirTemp("", "test-bucket")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		files["error"] = "this one causes an error"
		_, err = fetchFiles(context.TODO(), client, bucket, tmp)
		if err == nil {
			t.Fatal("expected error but got nil")
		}
	})

	t.Run("can fetch more than maxConcurrentFetches", func(t *testing.T) {
		// this will fail if, for example, the semaphore is not used correctly and blocks
		tmp, err := os.MkdirTemp("", "test-bucket")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		lotsOfFiles := map[string]string{}
		for i := 0; i < 2*maxConcurrentFetches; i++ {
			f := fmt.Sprintf("file-%d", i)
			lotsOfFiles[f] = f
		}
		lotsOfFilesClient := mockBucketClient{
			bucketName: bucketName,
			objects:    lotsOfFiles,
		}

		_, err = fetchFiles(context.TODO(), lotsOfFilesClient, bucket, tmp)
		if err != nil {
			t.Fatal(err)
		}
	})
}
