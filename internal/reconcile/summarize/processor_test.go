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
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
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

func TestNotifySuccess(t *testing.T) {
	tests := []struct {
		name             string
		oldObjBeforeFunc func(obj conditions.Setter)
		newObjBeforeFunc func(obj conditions.Setter)
		notification     Notification
		failConditions   []string
		result           reconcile.Result
		resultErr        error
		wantEvent        string
	}{
		{
			name: "fetch failed recovery",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultSuccess,
			wantEvent:      "resolved 'GitOperationFailed'",
		},
		{
			name: "fetch failed recovery with notification",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			notification: Notification{
				Reason:  "NewArtifact",
				Message: "stored artifact for commit 'Foo'",
				Annotations: map[string]string{
					"revision": "some-rev",
					"checksum": "some-checksum",
				},
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultSuccess,
			wantEvent:      "stored artifact for commit 'Foo'",
		},
		{
			name: "fetch failed, no recovery",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultSuccess,
		},
		{
			name: "notification without failure",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			notification: Notification{
				Reason:  "NewArtifact",
				Message: "stored artifact for commit 'Foo'",
				Annotations: map[string]string{
					"revision": "some-rev",
					"checksum": "some-checksum",
				},
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			wantEvent:      "stored artifact for commit 'Foo'",
			result:         reconcile.ResultSuccess,
		},
		{
			name:           "no notification, no failure",
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultSuccess,
		},
		{
			name: "empty result",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultEmpty,
		},
		{
			name: "error result",
			oldObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail msg foo")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "something failed")
			},
			newObjBeforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "artifact ready")
			},
			failConditions: []string{sourcev1.FetchFailedCondition, sourcev1.IncludeUnavailableCondition},
			result:         reconcile.ResultSuccess,
			resultErr:      fmt.Errorf("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.GitRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			resultProcessor := NotifySuccess(oldObj, tt.notification, tt.failConditions)

			resultProcessor(context.TODO(), recorder, newObj, tt.result, tt.resultErr)

			select {
			case x, ok := <-recorder.Events:
				g.Expect(ok).To(Equal(tt.wantEvent != ""), "unexpected event received")
				if tt.wantEvent != "" {
					g.Expect(x).To(ContainSubstring(tt.wantEvent))
				}
			default:
				if tt.wantEvent != "" {
					t.Errorf("expected some event to be emitted")
				}
			}
		})
	}
}
