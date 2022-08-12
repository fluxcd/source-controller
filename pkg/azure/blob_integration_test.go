//go:build integration

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

package azure

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

var (
	testTimeout = time.Second * 10
)

var (
	testAccountName = os.Getenv("TEST_AZURE_ACCOUNT_NAME")
	testAccountKey  = os.Getenv("TEST_AZURE_ACCOUNT_KEY")
)

var (
	testContainerGenerateName = "azure-client-test-"
	testFile                  = "test.yaml"
	testFileData              = `
---
test: file
`
	testFile2     = "test2.yaml"
	testFile2Data = `
---
test: file2
`
	testBucket = sourcev1.Bucket{
		Spec: sourcev1.BucketSpec{
			Endpoint: endpointURL(testAccountName),
		},
	}
	testSecret = corev1.Secret{
		Data: map[string][]byte{
			accountKeyField: []byte(testAccountKey),
		},
	}
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}

func TestBlobClient_BucketExists(t *testing.T) {
	g := NewWithT(t)

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Test if the container exists.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	ok, err := client.BucketExists(ctx, testContainer)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeTrue())
}

func TestBlobClient_BucketNotExists(t *testing.T) {
	g := NewWithT(t)

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Test if the container exists.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	ok, err := client.BucketExists(ctx, testContainer)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeFalse())
}

func TestBlobClient_FGetObject(t *testing.T) {
	g := NewWithT(t)

	tempDir := t.TempDir()

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Create test blob.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createBlob(ctx, client, testContainer, testFile, testFileData))

	localPath := filepath.Join(tempDir, testFile)

	// Test if blob exists.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	_, err = client.FGetObject(ctx, testContainer, testFile, localPath)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(localPath).To(BeARegularFile())
	f, _ := os.ReadFile(localPath)
	g.Expect(f).To(Equal([]byte(testFileData)))
}

func TestBlobClientSASKey_FGetObject(t *testing.T) {
	g := NewWithT(t)

	tempDir := t.TempDir()

	// create a client with the shared key
	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	g.Expect(client.CanGetAccountSASToken()).To(BeTrue())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Create test blob.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createBlob(ctx, client, testContainer, testFile, testFileData))

	localPath := filepath.Join(tempDir, testFile)

	// use the shared key client to create a SAS key for the account
	sasKey, err := client.GetSASToken(azblob.AccountSASResourceTypes{Object: true, Container: true},
		azblob.AccountSASPermissions{List: true, Read: true},
		azblob.AccountSASServices{Blob: true},
		time.Now(),
		time.Now().Add(48*time.Hour))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(sasKey).ToNot(BeEmpty())

	// the sdk returns the full SAS url e.g test.blob.core.windows.net/?<actual-sas-token>
	sasKey = strings.TrimPrefix(sasKey, testBucket.Spec.Endpoint+"/")
	testSASKeySecret := corev1.Secret{
		Data: map[string][]byte{
			sasKeyField: []byte(sasKey),
		},
	}

	sasKeyClient, err := NewClient(testBucket.DeepCopy(), testSASKeySecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())

	// Test if blob exists using sasKey.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	_, err = sasKeyClient.FGetObject(ctx, testContainer, testFile, localPath)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(localPath).To(BeARegularFile())
	f, _ := os.ReadFile(localPath)
	g.Expect(f).To(Equal([]byte(testFileData)))
}

func TestBlobClient_FGetObject_NotFoundErr(t *testing.T) {
	g := NewWithT(t)

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Test blob does not exist.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	_, err = client.FGetObject(ctx, testContainer, "doesnotexist.txt", "doesnotexist.txt")

	g.Expect(err).To(HaveOccurred())
	g.Expect(client.ObjectIsNotFound(err)).To(BeTrue())
}

func TestBlobClient_VisitObjects(t *testing.T) {
	g := NewWithT(t)

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Create test blobs.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createBlob(ctx, client, testContainer, testFile, testFileData))
	g.Expect(createBlob(ctx, client, testContainer, testFile2, testFile2Data))

	visits := make(map[string]string)

	// Visit objects.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	got := client.VisitObjects(ctx, testContainer, func(path, etag string) error {
		visits[path] = etag
		return nil
	})

	g.Expect(got).To(Succeed())
	g.Expect(visits[testFile]).ToNot(BeEmpty())
	g.Expect(visits[testFile2]).ToNot(BeEmpty())
	g.Expect(visits[testFile]).ToNot(Equal(visits[testFile2]))
}

func TestBlobClient_VisitObjects_CallbackErr(t *testing.T) {
	g := NewWithT(t)

	client, err := NewClient(testBucket.DeepCopy(), testSecret.DeepCopy())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client).ToNot(BeNil())

	// Generate test container name.
	testContainer := generateString(testContainerGenerateName)

	// Create test container.
	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createContainer(ctx, client, testContainer)).To(Succeed())
	t.Cleanup(func() {
		g.Expect(deleteContainer(context.Background(), client, testContainer)).To(Succeed())
	})

	// Create test blob.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	g.Expect(createBlob(ctx, client, testContainer, testFile, testFileData))

	// Visit object.
	ctx, timeout = context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	mockErr := fmt.Errorf("mock")
	err = client.VisitObjects(ctx, testContainer, func(path, etag string) error {
		return mockErr
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("mock"))
}

func createContainer(ctx context.Context, client *BlobClient, name string) error {
	if _, err := client.CreateContainer(ctx, name, nil); err != nil {
		var stgErr *azblob.StorageError
		if errors.As(err, &stgErr) {
			if stgErr.ErrorCode == azblob.StorageErrorCodeContainerAlreadyExists {
				return nil
			}
			err = stgErr
		}
		return err
	}
	return nil
}

func createBlob(ctx context.Context, client *BlobClient, containerName, name, data string) error {
	container := client.NewContainerClient(containerName)
	blob := container.NewAppendBlobClient(name)

	ctx, timeout := context.WithTimeout(context.Background(), testTimeout)
	defer timeout()
	if _, err := blob.Create(ctx, nil); err != nil {
		return err
	}

	hash := md5.Sum([]byte(data))
	if _, err := blob.AppendBlock(ctx, streaming.NopCloser(strings.NewReader(data)), &azblob.AppendBlockOptions{
		TransactionalContentMD5: hash[:16],
	}); err != nil {
		return err
	}
	return nil
}

func deleteContainer(ctx context.Context, client *BlobClient, name string) error {
	if _, err := client.DeleteContainer(ctx, name, nil); err != nil {
		var stgErr *azblob.StorageError
		if errors.As(err, &stgErr) {
			if code := stgErr.ErrorCode; code == azblob.StorageErrorCodeContainerNotFound ||
				code == azblob.StorageErrorCodeContainerBeingDeleted {
				return nil
			}
			err = stgErr
		}
		return err
	}
	return nil
}

func generateString(prefix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return prefix + hex.EncodeToString(randBytes)
}
