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

package summarize

import (
	"context"
	"errors"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/fluxcd/source-controller/internal/object"
	"github.com/fluxcd/source-controller/internal/reconcile"
)

func TestRecordReconcileReq(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(obj client.Object)
		afterFunc  func(t *WithT, obj client.Object)
	}{
		{
			name: "no reconcile req",
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt(""))
			},
		},
		{
			name: "no reconcile req, noop on existing value",
			beforeFunc: func(obj client.Object) {
				object.SetStatusLastHandledReconcileAt(obj, "zzz")
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("zzz"))
			},
		},
		{
			name: "with reconcile req",
			beforeFunc: func(obj client.Object) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "now",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("now"))
			},
		},
		// Additional test cases for bulletproof coverage:
		{
			name: "empty reconcile annotation value",
			beforeFunc: func(obj client.Object) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt(""))
			},
		},
		{
			name: "whitespace-only reconcile annotation value",
			beforeFunc: func(obj client.Object) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "   ",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("   "))
			},
		},
		{
			name: "reconcile annotation with special characters",
			beforeFunc: func(obj client.Object) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "2024-01-15T10:30:00Z",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("2024-01-15T10:30:00Z"))
			},
		},
		{
			name: "reconcile annotation with very long value",
			beforeFunc: func(obj client.Object) {
				longValue := strings.Repeat("a", 1000)
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: longValue,
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				longValue := strings.Repeat("a", 1000)
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt(longValue))
			},
		},
		{
			name: "reconcile annotation mixed with other annotations",
			beforeFunc: func(obj client.Object) {
				annotations := map[string]string{
					"some.other/annotation":         "other-value",
					meta.ReconcileRequestAnnotation: "mixed-test",
					"another/annotation":            "another-value",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("mixed-test"))
				t.Expect(obj.GetAnnotations()).To(HaveKeyWithValue("some.other/annotation", "other-value"))
				t.Expect(obj.GetAnnotations()).To(HaveKeyWithValue("another/annotation", "another-value"))
			},
		},
		{
			name: "reconcile annotation overwrites existing status value",
			beforeFunc: func(obj client.Object) {
				// Set initial status
				object.SetStatusLastHandledReconcileAt(obj, "old-value")
				// Then set annotation
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "new-value",
				}
				obj.SetAnnotations(annotations)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("new-value"))
			},
		},
		{
			name: "nil annotations map",
			beforeFunc: func(obj client.Object) {
				obj.SetAnnotations(nil)
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt(""))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-obj",
				},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}
			ctx := context.TODO()
			RecordReconcileReq(ctx, record.NewFakeRecorder(32), obj, reconcile.ResultEmpty, nil)
			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestRecordReconcileReq_ParameterHandling(t *testing.T) {
	g := NewWithT(t)
	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-obj",
			Annotations: map[string]string{
				meta.ReconcileRequestAnnotation: "param-test",
			},
		},
	}

	ctx := context.TODO()

	RecordReconcileReq(ctx, nil, obj, reconcile.ResultEmpty, nil)
	g.Expect(obj).To(HaveStatusLastHandledReconcileAt("param-test"))

	RecordReconcileReq(ctx, record.NewFakeRecorder(32), obj, reconcile.Result{Requeue: true}, nil)
	g.Expect(obj).To(HaveStatusLastHandledReconcileAt("param-test"))

	RecordReconcileReq(ctx, record.NewFakeRecorder(32), obj, reconcile.ResultEmpty, errors.New("test error"))
	g.Expect(obj).To(HaveStatusLastHandledReconcileAt("param-test"))
}
