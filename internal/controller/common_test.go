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
	"testing"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/patch"

	"github.com/fluxcd/source-controller/internal/object"
)

// durationSeriesExists reports whether gotk_reconcile_duration_seconds has a
// series for the given kind/name/namespace, read directly from the
// *prometheus.HistogramVec since the Recorder has no presence-check method.
func durationSeriesExists(t *testing.T, rec *metrics.Recorder, kind, name, namespace string) bool {
	t.Helper()

	var hv *prometheus.HistogramVec
	for _, c := range rec.Collectors() {
		if v, ok := c.(*prometheus.HistogramVec); ok {
			hv = v
			break
		}
	}
	if hv == nil {
		t.Fatal("no *prometheus.HistogramVec collector found on the recorder")
	}

	ch := make(chan prometheus.Metric, 64)
	hv.Collect(ch)
	close(ch)

	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("failed to write metric: %v", err)
		}
		labels := make(map[string]string, len(pb.GetLabel()))
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["kind"] == kind && labels["name"] == name && labels["namespace"] == namespace {
			return true
		}
	}
	return false
}

// waitForSourceDeletion is a generic test helper to wait for object deletion of
// any source kind.
func waitForSourceDeletion(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()

	key := client.ObjectKeyFromObject(obj)
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

// waitForSuspended is a generic test helper to wait for object to be suspended
// of any source kind.
func waitForSuspended(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()

	key := client.ObjectKeyFromObject(obj)
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		suspended, err := object.GetSuspend(obj)
		if err != nil {
			return false
		}
		return suspended == true
	}, timeout).Should(BeTrue())
}

// waitForSourceReadyWithArtifact is a generic test helper to wait for an object
// to be ready of any source kind that have artifact in status when ready.
func waitForSourceReadyWithArtifact(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()
	waitForSourceReady(ctx, g, obj, true)
}

// waitForSourceReady is a generic test helper to wait for an object to be
// ready of any source kind.
func waitForSourceReady(ctx context.Context, g *WithT, obj conditions.Setter, withArtifact bool) {
	g.THelper()

	key := client.ObjectKeyFromObject(obj)
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if withArtifact {
			artifact, err := object.GetArtifact(obj)
			if err != nil {
				return false
			}
			if artifact == nil {
				return false
			}
		}
		if !conditions.IsReady(obj) {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		statusObservedGen, err := object.GetStatusObservedGeneration(obj)
		if err != nil {
			return false
		}
		return obj.GetGeneration() == readyCondition.ObservedGeneration &&
			obj.GetGeneration() == statusObservedGen
	}, timeout).Should(BeTrue())
}

// testSuspendedObjectDeleteWithArtifact is a generic test helper to test if a
// suspended object can be deleted for objects that have artifact in status when
// ready.
func testSuspendedObjectDeleteWithArtifact(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()
	testSuspendedObjectDelete(ctx, g, obj, true)
}

// testSuspendedObjectDelete is a generic test helper to test if a suspended
// object can be deleted.
func testSuspendedObjectDelete(ctx context.Context, g *WithT, obj conditions.Setter, withArtifact bool) {
	g.THelper()

	// Create the object and wait for it to be ready.
	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())
	waitForSourceReady(ctx, g, obj, withArtifact)

	// Suspend the object.
	patchHelper, err := patch.NewHelper(obj, testEnv.Client)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(object.SetSuspend(obj, true)).ToNot(HaveOccurred())
	g.Expect(patchHelper.Patch(ctx, obj)).ToNot(HaveOccurred())
	waitForSuspended(ctx, g, obj)

	// Delete the object.
	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())
	waitForSourceDeletion(ctx, g, obj)
}
