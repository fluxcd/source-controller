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

package gcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/assert"
)

func TestNewClient(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	client, err := NewClient(context.Background())
	assert.NilError(t, err)
	assert.Assert(t, client.Client != nil)
}

func TestSetRange(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	client, err := NewClient(context.Background())
	assert.NilError(t, err)
	testCases := []struct {
		title string
		start int64
		end   int64
	}{
		{
			title: "Test Case 1",
			start: 1,
			end:   5,
		},
		{
			title: "Test Case 2",
			start: 3,
			end:   6,
		},
		{
			title: "Test Case 3",
			start: 4,
			end:   5,
		},
		{
			title: "Test Case 4",
			start: 2,
			end:   7,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.title, func(t *testing.T) {
			client.SetRange(tt.start, tt.end)
			assert.Equal(t, tt.start, client.startRange)
			assert.Equal(t, tt.end, client.endRange)
		})
	}
}

func TestBucketExists(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	ctx := context.Background()
	bucketName := ""
	client, err := NewClient(ctx)
	assert.NilError(t, err)
	exists, err := client.BucketExists(ctx, bucketName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestObjectExists(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	ctx := context.Background()
	// bucketName is the name of the bucket which contains the object
	bucketName := ""
	// objectName is the path to the object within the bucket
	objectName := ""
	client, err := NewClient(ctx)
	assert.NilError(t, err)
	exists, attrs, err := client.ObjectExists(ctx, bucketName, objectName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
	assert.Assert(t, attrs != nil)
}

func TestListObjects(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	ctx := context.Background()
	// bucketName is the name of the bucket which contains the object
	bucketName := ""
	client, err := NewClient(ctx)
	assert.NilError(t, err)
	objects := client.ListObjects(ctx, bucketName, nil)
	assert.NilError(t, err)
	assert.Assert(t, objects != nil)
	for {
		object, err := objects.Next()
		if err == IteratorDone {
			break
		}
		assert.Assert(t, object != nil)
	}
}

func TestFGetObject(t *testing.T) {
	// TODO: Setup GCP mock here
	t.Skip()
	ctx := context.Background()
	// bucketName is the name of the bucket which contains the object
	bucketName := ""
	// objectName is the path to the object within the bucket
	objectName := ""
	tempDir, err := os.MkdirTemp("", bucketName)
	if err != nil {
		assert.NilError(t, err)
	}
	localPath := filepath.Join(tempDir, objectName)
	client, err := NewClient(ctx)
	assert.NilError(t, err)
	objErr := client.FGetObject(ctx, bucketName, objectName, localPath)
	assert.NilError(t, objErr)
}
