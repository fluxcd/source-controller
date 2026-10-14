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
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	runtimectrl "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

func TestBucketReconciler_deleteMetricsOnNotFound(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	const namespaceName = "bucket-metrics-test"
	const name = "metrics-test"

	obj := &sourcev1.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespaceName,
			Finalizers: []string{sourcev1.SourceFinalizer},
		},
		Spec: sourcev1.BucketSpec{
			BucketName: "does-not-exist",
			Endpoint:   "example.com",
			Interval:   metav1.Duration{Duration: time.Hour},
			Timeout:    &metav1.Duration{Duration: 5 * time.Second},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithStatusSubresource(&sourcev1.Bucket{}).
		WithObjects(obj).
		Build()

	rec := metrics.NewRecorder()

	r := &BucketReconciler{
		Client:   fakeClient,
		Recorder: events.NewFakeRecorder(32, false),
		Storage:  testStorage,
		Metrics: runtimectrl.Metrics{
			Scheme:          scheme.Scheme,
			MetricsRecorder: rec,
		},
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}

	_, _ = r.Reconcile(ctx, req)
	g.Expect(durationSeriesExists(t, rec, sourcev1.BucketKind, name, namespaceName)).
		To(BeTrue(), "expected a duration series after the first (successful Get) reconcile")

	g.Expect(fakeClient.Get(ctx, req.NamespacedName, obj)).To(Succeed())
	obj.SetFinalizers(nil)
	g.Expect(fakeClient.Update(ctx, obj)).To(Succeed())
	g.Expect(fakeClient.Delete(ctx, obj)).To(Succeed())

	err := fakeClient.Get(ctx, req.NamespacedName, &sourcev1.Bucket{})
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "object must be fully gone (NotFound), not merely marked for deletion")

	_, err = r.Reconcile(ctx, req)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(durationSeriesExists(t, rec, sourcev1.BucketKind, name, namespaceName)).
		To(BeFalse(), "duration series must not survive the object's deletion")
}
