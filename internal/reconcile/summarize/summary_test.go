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
	"fmt"
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/reconcile"
)

// This tests the scenario where SummarizeAndPatch is used at the very end of a
// reconciliation.
func TestSummarizeAndPatch(t *testing.T) {
	var testReadyConditions = Conditions{
		Target: meta.ReadyCondition,
		Owned: []string{
			sourcev1.FetchFailedCondition,
			sourcev1.ArtifactOutdatedCondition,
			meta.ReadyCondition,
			meta.ReconcilingCondition,
			meta.StalledCondition,
		},
		Summarize: []string{
			sourcev1.FetchFailedCondition,
			sourcev1.ArtifactOutdatedCondition,
			meta.StalledCondition,
			meta.ReconcilingCondition,
		},
		NegativePolarity: []string{
			sourcev1.FetchFailedCondition,
			sourcev1.ArtifactOutdatedCondition,
			meta.StalledCondition,
			meta.ReconcilingCondition,
		},
	}
	var testFooConditions = Conditions{
		Target: "Foo",
		Owned: []string{
			"Foo",
			"AAA",
			"BBB",
		},
		Summarize: []string{
			"AAA",
			"BBB",
		},
		NegativePolarity: []string{
			"BBB",
		},
	}

	tests := []struct {
		name             string
		generation       int64
		beforeFunc       func(obj conditions.Setter)
		result           reconcile.Result
		reconcileErr     error
		conditions       []Conditions
		wantErr          bool
		afterFunc        func(t *WithT, obj client.Object)
		assertConditions []metav1.Condition
	}{
		// Success/Fail indicates if a reconciliation succeeded or failed.
		// The object generation is expected to match the observed generation in
		// the object status if Ready=True or Stalled=True at the end.
		// All the cases have some Ready condition set, even if a test case is
		// unrelated to the conditions, because it's neseccary for a valid
		// status.
		{
			name:       "Success, Ready=True",
			generation: 4,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
			},
			result:     reconcile.ResultSuccess,
			conditions: []Conditions{testReadyConditions},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusObservedGeneration(4))
			},
		},
		{
			name:       "Success, removes reconciling for successful result",
			generation: 2,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkReconciling(obj, "NewRevision", "new index version")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "stored artifact")
			},
			conditions: []Conditions{testReadyConditions},
			result:     reconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusObservedGeneration(2))
			},
		},
		{
			name: "Success, record reconciliation request",
			beforeFunc: func(obj conditions.Setter) {
				annotations := map[string]string{
					meta.ReconcileRequestAnnotation: "now",
				}
				obj.SetAnnotations(annotations)
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
			},
			generation: 3,
			conditions: []Conditions{testReadyConditions},
			result:     reconcile.ResultSuccess,
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusLastHandledReconcileAt("now"))
				t.Expect(obj).To(HaveStatusObservedGeneration(3))
			},
		},
		{
			name:       "Fail, with multiple conditions ArtifactOutdated=True,Reconciling=True",
			generation: 7,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
				conditions.MarkReconciling(obj, "NewRevision", "new index revision")
			},
			conditions:   []Conditions{testReadyConditions},
			reconcileErr: fmt.Errorf("failed to create dir"),
			wantErr:      true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new index revision"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).ToNot(HaveStatusObservedGeneration(7))
			},
		},
		{
			name:       "Success, with subreconciler stalled error",
			generation: 9,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.FetchFailedCondition, "failed to construct client")
			},
			conditions:   []Conditions{testReadyConditions},
			reconcileErr: &serror.Stalling{Err: fmt.Errorf("some error"), Reason: "some reason"},
			wantErr:      false,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.FetchFailedCondition, "failed to construct client"),
				*conditions.TrueCondition(meta.StalledCondition, "some reason", "some error"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.FetchFailedCondition, "failed to construct client"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).To(HaveStatusObservedGeneration(9))
			},
		},
		{
			name:       "Fail, no error but requeue requested",
			generation: 3,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "test-msg")
			},
			conditions: []Conditions{testReadyConditions},
			result:     reconcile.ResultRequeue,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, meta.FailedReason, "test-msg"),
			},
			afterFunc: func(t *WithT, obj client.Object) {
				t.Expect(obj).ToNot(HaveStatusObservedGeneration(3))
			},
		},
		{
			name:       "Success, multiple target conditions summary",
			generation: 3,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
				conditions.MarkTrue(obj, "AAA", "ZZZ", "zzz") // Positive polarity True.
			},
			conditions: []Conditions{testReadyConditions, testFooConditions},
			result:     reconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
				*conditions.TrueCondition("Foo", "ZZZ", "zzz"), // True summary.
				*conditions.TrueCondition("AAA", "ZZZ", "zzz"),
			},
		},
		{
			name:       "Success, multiple target conditions, False non-Ready summary don't affect result",
			generation: 3,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "test-msg")
				conditions.MarkTrue(obj, "AAA", "ZZZ", "zzz") // Positive polarity True.
				conditions.MarkTrue(obj, "BBB", "YYY", "yyy") // Negative polarity True.
			},
			conditions: []Conditions{testReadyConditions, testFooConditions},
			result:     reconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "test-msg"),
				*conditions.FalseCondition("Foo", "YYY", "yyy"), // False summary.
				*conditions.TrueCondition("BBB", "YYY", "yyy"),
				*conditions.TrueCondition("AAA", "ZZZ", "zzz"),
			},
		},
		{
			name:       "Fail, success result but Ready=False",
			generation: 3,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision")
			},
			conditions: []Conditions{testReadyConditions},
			result:     reconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, "NewRevision", "new index revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new index revision"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			scheme := runtime.NewScheme()
			g.Expect(sourcev1.AddToScheme(scheme))

			builder := fakeclient.NewClientBuilder().WithScheme(scheme)
			client := builder.Build()
			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   tt.generation,
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval: metav1.Duration{Duration: 5 * time.Second},
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			g.Expect(client.Create(ctx, obj)).To(Succeed())
			patchHelper, err := patch.NewHelper(obj, client)
			g.Expect(err).ToNot(HaveOccurred())

			summaryHelper := NewHelper(record.NewFakeRecorder(32), patchHelper)
			summaryOpts := []Option{
				WithReconcileResult(tt.result),
				WithReconcileError(tt.reconcileErr),
				WithConditions(tt.conditions...),
				WithIgnoreNotFound(),
				WithProcessors(RecordContextualError, RecordReconcileReq),
				WithResultBuilder(reconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.Spec.Interval.Duration}),
			}
			_, gotErr := summaryHelper.SummarizeAndPatch(ctx, obj, summaryOpts...)
			g.Expect(gotErr != nil).To(Equal(tt.wantErr))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}

			// Check if the object status is valid as per kstatus.
			condns := &status.Conditions{NegativePolarity: testReadyConditions.NegativePolarity}
			checker := status.NewChecker(client, condns)
			checker.CheckErr(ctx, obj)
		})
	}
}

// This tests the scenario where SummarizeAndPatch is used in the middle of
// reconciliation.
func TestSummarizeAndPatch_Intermediate(t *testing.T) {
	interval := 5 * time.Second

	var testStageAConditions = Conditions{
		Target:           "StageA",
		Owned:            []string{"StageA", "A1", "A2", "A3"},
		Summarize:        []string{"A1", "A2", "A3"},
		NegativePolarity: []string{"A3"},
	}
	var testStageBConditions = Conditions{
		Target:           "StageB",
		Owned:            []string{"StageB", "B1", "B2"},
		Summarize:        []string{"B1", "B2"},
		NegativePolarity: []string{"B1"},
	}

	tests := []struct {
		name             string
		conditions       []Conditions
		beforeFunc       func(obj conditions.Setter)
		assertConditions []metav1.Condition
	}{
		{
			name:       "single Conditions, True summary",
			conditions: []Conditions{testStageAConditions},
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "A1", "ZZZ", "zzz") // Positive polarity True.
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition("StageA", "ZZZ", "zzz"), // True summary.
				*conditions.TrueCondition("A1", "ZZZ", "zzz"),
			},
		},
		{
			name:       "single Conditions, False summary",
			conditions: []Conditions{testStageAConditions},
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "A1", "ZZZ", "zzz") // Positive polarity True.
				conditions.MarkTrue(obj, "A3", "OOO", "ooo") // Negative polarity True.
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition("StageA", "OOO", "ooo"), // False summary.
				*conditions.TrueCondition("A3", "OOO", "ooo"),
				*conditions.TrueCondition("A1", "ZZZ", "zzz"),
			},
		},
		{
			name:       "multiple Conditions, mixed results",
			conditions: []Conditions{testStageAConditions, testStageBConditions},
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "A3", "ZZZ", "zzz") // Negative polarity True.
				conditions.MarkTrue(obj, "B2", "RRR", "rrr") // Positive polarity True.
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition("StageA", "ZZZ", "zzz"), // False summary.
				*conditions.TrueCondition("A3", "ZZZ", "zzz"),
				*conditions.TrueCondition("StageB", "RRR", "rrr"), // True summary.
				*conditions.TrueCondition("B2", "RRR", "rrr"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			scheme := runtime.NewScheme()
			g.Expect(sourcev1.AddToScheme(scheme))

			builder := fakeclient.NewClientBuilder().WithScheme(scheme)
			kclient := builder.Build()

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
				},
				Status: sourcev1.GitRepositoryStatus{
					Conditions: []metav1.Condition{
						*conditions.FalseCondition("StageA", "QQQ", "qqq"),
					},
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			g.Expect(kclient.Create(ctx, obj)).To(Succeed())
			patchHelper, err := patch.NewHelper(obj, kclient)
			g.Expect(err).ToNot(HaveOccurred())

			summaryHelper := NewHelper(record.NewFakeRecorder(32), patchHelper)
			summaryOpts := []Option{
				WithConditions(tt.conditions...),
				WithResultBuilder(reconcile.AlwaysRequeueResultBuilder{RequeueAfter: interval}),
			}
			_, err = summaryHelper.SummarizeAndPatch(ctx, obj, summaryOpts...)
			g.Expect(err).ToNot(HaveOccurred())

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestIsNonStalledSuccess(t *testing.T) {
	interval := 5 * time.Second

	tests := []struct {
		name       string
		beforeFunc func(obj conditions.Setter)
		rb         reconcile.RuntimeResultBuilder
		recResult  ctrl.Result
		recErr     error
		wantResult bool
	}{
		{
			name:       "non stalled success",
			rb:         reconcile.AlwaysRequeueResultBuilder{RequeueAfter: interval},
			recResult:  ctrl.Result{RequeueAfter: interval},
			wantResult: true,
		},
		{
			name: "stalled success",
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkStalled(obj, "FooReason", "test-msg")
			},
			rb:         reconcile.AlwaysRequeueResultBuilder{RequeueAfter: interval},
			recResult:  ctrl.Result{RequeueAfter: interval},
			wantResult: false,
		},
		{
			name:       "error result",
			rb:         reconcile.AlwaysRequeueResultBuilder{RequeueAfter: interval},
			recResult:  ctrl.Result{RequeueAfter: interval},
			recErr:     errors.New("some-error"),
			wantResult: false,
		},
		{
			name:       "non success result",
			rb:         reconcile.AlwaysRequeueResultBuilder{RequeueAfter: interval},
			recResult:  ctrl.Result{RequeueAfter: 2 * time.Second},
			wantResult: false,
		},
		{
			name:       "no result builder",
			recResult:  ctrl.Result{RequeueAfter: interval},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}
			g.Expect(isNonStalledSuccess(obj, tt.rb, tt.recResult, tt.recErr)).To(Equal(tt.wantResult))
		})
	}
}
