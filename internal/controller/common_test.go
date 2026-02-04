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

	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"

	"github.com/werf/nelm-source-controller/internal/object"
)

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

// waitForSourceReadyWithoutArtifact is a generic test helper to wait for an object
// to be ready of any source kind that don't have artifact in status when ready.
func waitForSourceReadyWithoutArtifact(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()
	waitForSourceReady(ctx, g, obj, false)
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

// testSuspendedObjectDeleteWithoutArtifact is a generic test helper to test if
// a suspended object can be deleted for objects that don't have artifact in
// status when ready.
func testSuspendedObjectDeleteWithoutArtifact(ctx context.Context, g *WithT, obj conditions.Setter) {
	g.THelper()
	testSuspendedObjectDelete(ctx, g, obj, false)
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
