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

package gcp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	gcpStorage "cloud.google.com/go/storage"
	"github.com/fluxcd/source-controller/pkg/gcp"
	"github.com/fluxcd/source-controller/pkg/gcp/mocks"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	MockCtrl         *gomock.Controller
	MockClient       *mocks.MockClient
	MockBucketHandle *mocks.MockBucketHandle
	MockObjectHandle *mocks.MockObjectHandle
	bucketName       string = "test-bucket"
	objectName       string = "test.yaml"
	localPath        string
)

// mockgen -destination=mocks/mock_gcp_storage.go -package=mocks -source=gcp.go GCPStorageService
func TestGCPProvider(t *testing.T) {
	MockCtrl = gomock.NewController(GinkgoT())
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test GCP Storage Provider Suite")
}

var _ = BeforeSuite(func() {
	MockClient = mocks.NewMockClient(MockCtrl)
	MockBucketHandle = mocks.NewMockBucketHandle(MockCtrl)
	MockObjectHandle = mocks.NewMockObjectHandle(MockCtrl)
	tempDir, err := os.MkdirTemp("", bucketName)
	if err != nil {
		Expect(err).ToNot(HaveOccurred())
	}
	localPath = filepath.Join(tempDir, objectName)
	MockClient.EXPECT().Bucket(bucketName).Return(MockBucketHandle).AnyTimes()
	MockBucketHandle.EXPECT().Object(objectName).Return(&gcpStorage.ObjectHandle{}).AnyTimes()
	MockBucketHandle.EXPECT().Attrs(context.Background()).Return(&gcpStorage.BucketAttrs{
		Name:    bucketName,
		Created: time.Now(),
		Etag:    "test-etag",
	}, nil).AnyTimes()
	MockBucketHandle.EXPECT().Objects(gomock.Any(), nil).Return(&gcpStorage.ObjectIterator{}).AnyTimes()
	MockObjectHandle.EXPECT().Attrs(gomock.Any()).Return(&gcpStorage.ObjectAttrs{
		Bucket:      bucketName,
		Name:        objectName,
		ContentType: "text/x-yaml",
		Etag:        "test-etag",
		Size:        125,
		Created:     time.Now(),
	}, nil).AnyTimes()
	MockObjectHandle.EXPECT().NewRangeReader(gomock.Any(), 10, 125).Return(&gcpStorage.Reader{}, nil).AnyTimes()
})

var _ = Describe("GCP Storage Provider", func() {
	Describe("Get GCP Storage Provider client from gcp", func() {

		Context("Gcp storage Bucket - BucketExists", func() {
			It("should not return an error when fetching gcp storage bucket", func() {
				gcpClient := &gcp.GCPClient{
					Client:     MockClient,
					StartRange: 0,
					EndRange:   -1,
				}
				exists, err := gcpClient.BucketExists(context.Background(), bucketName)
				Expect(err).ToNot(HaveOccurred())
				Expect(exists).To(BeTrue())
			})
		})
		Context("Gcp storage Bucket - FGetObject", func() {
			It("should get the object from the bucket and download the object locally", func() {
				gcpClient := &gcp.GCPClient{
					Client:     MockClient,
					StartRange: 0,
					EndRange:   -1,
				}
				err := gcpClient.FGetObject(context.Background(), bucketName, objectName, localPath)
				Expect(err).ToNot(HaveOccurred())
			})
		})
		Context("Gcp storage Bucket - ObjectAttributes", func() {
			It("should get the object attributes", func() {
				gcpClient := &gcp.GCPClient{
					Client:     MockClient,
					StartRange: 0,
					EndRange:   -1,
				}
				exists, attrs, err := gcpClient.ObjectAttributes(context.Background(), bucketName, objectName)
				Expect(err).ToNot(HaveOccurred())
				Expect(exists).To(BeTrue())
				Expect(attrs).ToNot(BeNil())
			})

			Context("Gcp storage Bucket - SetRange", func() {
				It("should set the range of the io reader seeker for the file download", func() {
					gcpClient := &gcp.GCPClient{
						Client:     MockClient,
						StartRange: 0,
						EndRange:   -1,
					}
					gcpClient.SetRange(2, 5)
					Expect(gcpClient.StartRange).To(Equal(int64(2)))
					Expect(gcpClient.EndRange).To(Equal(int64(5)))
				})
			})
		})
	})
})
