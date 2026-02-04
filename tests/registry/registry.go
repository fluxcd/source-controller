/*
Copyright 2024 The Flux authors

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

package testregistry

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/google/go-containerregistry/pkg/crane"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/fluxcd/pkg/oci"

	testlistener "github.com/werf/nelm-source-controller/tests/listener"
)

func New(t *testing.T) string {
	t.Helper()

	// Get a free random port and release it so the registry can use it.
	listener, addr, _ := testlistener.New(t)
	err := listener.Close()
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())

	config := &configuration.Configuration{}
	config.HTTP.Addr = addr
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	config.Log.AccessLog.Disabled = true
	config.Log.Level = "error"
	logrus.SetOutput(io.Discard)

	r, err := registry.NewRegistry(context.Background(), config)
	g.Expect(err).NotTo(HaveOccurred())

	go r.ListenAndServe()

	return addr
}

type PodinfoImage struct {
	URL    string
	Tag    string
	Digest gcrv1.Hash
}

func CreatePodinfoImageFromTar(tarFilePath, tag, registryURL string, opts ...crane.Option) (*PodinfoImage, error) {
	// Create Image
	image, err := crane.Load(tarFilePath)
	if err != nil {
		return nil, err
	}

	image = setPodinfoImageAnnotations(image, tag)

	// url.Parse doesn't handle urls with no scheme well e.g localhost:<port>
	if !(strings.HasPrefix(registryURL, "http://") || strings.HasPrefix(registryURL, "https://")) {
		registryURL = fmt.Sprintf("http://%s", registryURL)
	}

	myURL, err := url.Parse(registryURL)
	if err != nil {
		return nil, err
	}
	repositoryURL := fmt.Sprintf("%s/podinfo", myURL.Host)

	// Image digest
	podinfoImageDigest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	// Push image
	err = crane.Push(image, repositoryURL, opts...)
	if err != nil {
		return nil, err
	}

	// Tag the image
	err = crane.Tag(repositoryURL, tag, opts...)
	if err != nil {
		return nil, err
	}

	return &PodinfoImage{
		URL:    "oci://" + repositoryURL,
		Tag:    tag,
		Digest: podinfoImageDigest,
	}, nil
}

func setPodinfoImageAnnotations(img gcrv1.Image, tag string) gcrv1.Image {
	metadata := map[string]string{
		oci.SourceAnnotation:   "https://github.com/stefanprodan/podinfo",
		oci.RevisionAnnotation: fmt.Sprintf("%s@sha1:b3b00fe35424a45d373bf4c7214178bc36fd7872", tag),
	}
	return mutate.Annotations(img, metadata).(gcrv1.Image)
}
