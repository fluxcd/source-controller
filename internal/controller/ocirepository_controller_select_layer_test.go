/*
Copyright 2026 The Flux authors

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
	"io"
	"testing"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/gomega"
)

const (
	helmChartLayerMediaType      = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	helmProvenanceLayerMediaType = "application/vnd.cncf.helm.chart.provenance.v1.prov"
)

func TestSelectLayerHelmProvenanceFirst(t *testing.T) {
	g := NewWithT(t)

	provenance := []byte("provenance file")
	chart := []byte("chart archive")
	provenanceLayer := static.NewLayer(provenance, types.MediaType(helmProvenanceLayerMediaType))
	chartLayer := static.NewLayer(chart, types.MediaType(helmChartLayerMediaType))
	img, err := mutate.AppendLayers(empty.Image, provenanceLayer, chartLayer)
	g.Expect(err).NotTo(HaveOccurred())

	reconciler := &OCIRepositoryReconciler{}
	obj := &sourcev1.OCIRepository{}
	blob, err := reconciler.selectLayer(obj, gcrv1.Image(img))
	g.Expect(err).NotTo(HaveOccurred())
	defer blob.Close()

	got, err := io.ReadAll(blob)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(chart))
}

func TestSelectLayerHelmChartFirstRemainsUnchanged(t *testing.T) {
	g := NewWithT(t)

	chart := []byte("chart archive")
	provenance := []byte("provenance file")
	chartLayer := static.NewLayer(chart, types.MediaType(helmChartLayerMediaType))
	provenanceLayer := static.NewLayer(provenance, types.MediaType(helmProvenanceLayerMediaType))
	img, err := mutate.AppendLayers(empty.Image, chartLayer, provenanceLayer)
	g.Expect(err).NotTo(HaveOccurred())

	reconciler := &OCIRepositoryReconciler{}
	obj := &sourcev1.OCIRepository{}
	blob, err := reconciler.selectLayer(obj, gcrv1.Image(img))
	g.Expect(err).NotTo(HaveOccurred())
	defer blob.Close()

	got, err := io.ReadAll(blob)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(chart))
}
