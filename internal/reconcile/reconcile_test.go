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

package reconcile

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
)

func TestLowestRequeuingResult(t *testing.T) {
	tests := []struct {
		name       string
		i          Result
		j          Result
		wantResult Result
	}{
		{"bail,requeue", ResultEmpty, ResultRequeue, ResultRequeue},
		{"bail,requeueInterval", ResultEmpty, ResultSuccess, ResultSuccess},
		{"requeue,bail", ResultRequeue, ResultEmpty, ResultRequeue},
		{"requeue,requeueInterval", ResultRequeue, ResultSuccess, ResultRequeue},
		{"requeueInterval,requeue", ResultSuccess, ResultRequeue, ResultRequeue},
		{"requeueInterval,requeueInterval", ResultSuccess, ResultSuccess, ResultSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(LowestRequeuingResult(tt.i, tt.j)).To(Equal(tt.wantResult))
		})
	}
}

// This test uses AlwaysRequeueResultBuilder as the RuntimeResultBuilder.
func TestComputeReconcileResult(t *testing.T) {
	testSuccessInterval := time.Minute
	tests := []struct {
		name             string
		result           Result
		beforeFunc       func(obj conditions.Setter)
		recErr           error
		wantResult       ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
		afterFunc        func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions)
	}{
		{
			name:   "successful result",
			result: ResultSuccess,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			recErr:     nil,
			wantResult: ctrl.Result{RequeueAfter: testSuccessInterval},
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "foo"),
			},
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeTrue())
			},
		},
		{
			name:   "successful result, Reconciling=True, remove Reconciling",
			result: ResultSuccess,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkReconciling(obj, "NewRevision", "new revision")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			recErr:     nil,
			wantResult: ctrl.Result{RequeueAfter: testSuccessInterval},
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "foo"),
			},
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeTrue())
				t.Expect(conditions.IsUnknown(obj, meta.ReconcilingCondition)).To(BeTrue())
			},
		},
		{
			name:   "successful result, Stalled=True, remove Stalled",
			result: ResultSuccess,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkStalled(obj, "SomeReason", "some message")
			},
			recErr:     nil,
			wantResult: ctrl.Result{RequeueAfter: testSuccessInterval},
			wantErr:    false,
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeTrue())
				t.Expect(conditions.IsUnknown(obj, meta.StalledCondition)).To(BeTrue())
			},
		},
		{
			name:       "requeue result",
			result:     ResultRequeue,
			recErr:     nil,
			wantResult: ctrl.Result{Requeue: true},
			wantErr:    false,
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeFalse())
			},
		},
		{
			name:       "stalling error",
			result:     ResultEmpty,
			recErr:     &serror.Stalling{Err: fmt.Errorf("some error"), Reason: "some reason"},
			wantResult: ctrl.Result{},
			wantErr:    false,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.StalledCondition, "some reason", "some error"),
			},
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeTrue())
			},
		},
		{
			name:       "waiting error",
			result:     ResultEmpty,
			recErr:     &serror.Waiting{Err: fmt.Errorf("some error"), Reason: "some reason"},
			wantResult: ctrl.Result{RequeueAfter: testSuccessInterval},
			wantErr:    false,
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeFalse())
			},
		},
		{
			name:   "generic error, Stalled=True, remove Stalled",
			result: ResultEmpty,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkStalled(obj, "SomeReason", "some message")
			},
			recErr: &serror.Generic{
				Err: fmt.Errorf("some error"), Reason: "some reason",
			},
			wantResult: ctrl.Result{},
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(conditions.IsUnknown(obj, meta.StalledCondition)).To(BeTrue())
			},
			wantErr: true,
		},
		{
			name:   "generic ignore error, Reconciling=True, remove Reconciling",
			result: ResultEmpty,
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkReconciling(obj, "NewRevision", "new revision")
			},
			recErr: &serror.Generic{
				Err: fmt.Errorf("some error"), Reason: "some reason",
				Config: serror.Config{
					Ignore: true,
				},
			},
			wantResult: ctrl.Result{RequeueAfter: testSuccessInterval},
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeTrue())
				t.Expect(conditions.IsUnknown(obj, meta.ReconcilingCondition)).To(BeTrue())
			},
			wantErr: false,
		},
		{
			name:       "random error",
			result:     ResultEmpty,
			recErr:     fmt.Errorf("some error"),
			wantResult: ctrl.Result{},
			wantErr:    true,
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeFalse())
			},
		},
		{
			name:       "random error, Stalled=True, remove Stalled",
			result:     ResultEmpty,
			recErr:     fmt.Errorf("some error"),
			wantResult: ctrl.Result{},
			wantErr:    true,
			afterFunc: func(t *WithT, obj conditions.Setter, patchOpts *patch.HelperOptions) {
				t.Expect(patchOpts.IncludeStatusObservedGeneration).To(BeFalse())
				t.Expect(conditions.IsUnknown(obj, meta.StalledCondition)).To(BeTrue())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{}
			obj.Name = "test-git-repo"
			obj.Namespace = "default"
			obj.Spec.Interval = metav1.Duration{Duration: testSuccessInterval}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			rb := AlwaysRequeueResultBuilder{RequeueAfter: obj.Spec.Interval.Duration}
			pOpts, result, err := ComputeReconcileResult(obj, tt.result, tt.recErr, rb)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(result).To(Equal(tt.wantResult))

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			opts := &patch.HelperOptions{}
			for _, o := range pOpts {
				o.ApplyToHelper(opts)
			}
			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, opts)
			}
		})
	}
}

func TestAlwaysRequeueResultBuilder_IsSuccess(t *testing.T) {
	interval := 5 * time.Second

	tests := []struct {
		name          string
		resultBuilder AlwaysRequeueResultBuilder
		runtimeResult ctrl.Result
		result        bool
	}{
		{
			name:          "success result",
			resultBuilder: AlwaysRequeueResultBuilder{RequeueAfter: interval},
			runtimeResult: ctrl.Result{RequeueAfter: interval},
			result:        true,
		},
		{
			name:          "requeue result",
			resultBuilder: AlwaysRequeueResultBuilder{RequeueAfter: interval},
			runtimeResult: ctrl.Result{Requeue: true},
			result:        false,
		},
		{
			name:          "zero result",
			resultBuilder: AlwaysRequeueResultBuilder{RequeueAfter: interval},
			runtimeResult: ctrl.Result{},
			result:        false,
		},
		{
			name:          "different requeue after",
			resultBuilder: AlwaysRequeueResultBuilder{RequeueAfter: interval},
			runtimeResult: ctrl.Result{RequeueAfter: time.Second},
			result:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(tt.resultBuilder.IsSuccess(tt.runtimeResult)).To(Equal(tt.result))
		})
	}
}

func TestFailureRecovery(t *testing.T) {
	failCondns := []string{
		"FooFailed",
		"BarFailed",
		"BazFailed",
	}
	tests := []struct {
		name           string
		oldObjFunc     func(obj conditions.Setter)
		newObjFunc     func(obj conditions.Setter)
		failConditions []string
		result         bool
	}{
		{
			name: "no failures",
			oldObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			failConditions: failCondns,
			result:         false,
		},
		{
			name: "no recovery",
			oldObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "FooFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "FooFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			failConditions: failCondns,
			result:         false,
		},
		{
			name: "different failure",
			oldObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "FooFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "BarFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			failConditions: failCondns,
			result:         false,
		},
		{
			name: "failure recovery",
			oldObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "FooFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			failConditions: failCondns,
			result:         true,
		},
		{
			name: "ready to fail",
			oldObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, "BazFailed", "some-reason", "message")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			failConditions: failCondns,
			result:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			oldObj := &sourcev1.GitRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjFunc != nil {
				tt.oldObjFunc(oldObj)
			}

			if tt.newObjFunc != nil {
				tt.newObjFunc(newObj)
			}

			g.Expect(FailureRecovery(oldObj, newObj, tt.failConditions)).To(Equal(tt.result))
		})
	}
}

func TestAddOptionWithStatusObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(obj conditions.Setter)
		patchOpts  []patch.Option
		want       bool
	}{
		{
			name: "no conditions",
			want: false,
		},
		{
			name: "some condition",
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			want: true,
		},
		{
			name: "existing option with conditions",
			beforeFunc: func(obj conditions.Setter) {
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			patchOpts: []patch.Option{patch.WithForceOverwriteConditions{}, patch.WithStatusObservedGeneration{}},
			want:      true,
		},
		{
			name:      "existing option, no conditions, can't remove",
			patchOpts: []patch.Option{patch.WithForceOverwriteConditions{}, patch.WithStatusObservedGeneration{}},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			tt.patchOpts = addPatchOptionWithStatusObservedGeneration(obj, tt.patchOpts)

			// Apply the options and evaluate the result.
			options := &patch.HelperOptions{}
			for _, opt := range tt.patchOpts {
				opt.ApplyToHelper(options)
			}
			g.Expect(options.IncludeStatusObservedGeneration).To(Equal(tt.want))
		})
	}
}
