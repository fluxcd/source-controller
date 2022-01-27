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
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"

	serror "github.com/fluxcd/source-controller/internal/error"
)

// Result is a type for creating an abstraction for the controller-runtime
// reconcile Result to simplify the Result values.
type Result int

const (
	// ResultEmpty indicates a reconcile result which does not requeue.
	ResultEmpty Result = iota
	// ResultRequeue indicates a reconcile result which should immediately
	// requeue.
	ResultRequeue
	// ResultSuccess indicates a reconcile result which should be
	// requeued on the interval as defined on the reconciled object.
	ResultSuccess
)

// BuildRuntimeResult converts a given Result and error into the
// return values of a controller's Reconcile function.
// func BuildRuntimeResult(ctx context.Context, recorder kuberecorder.EventRecorder, obj sourcev1.Source, rr Result, err error) (ctrl.Result, error) {
func BuildRuntimeResult(successInterval time.Duration, rr Result, err error) ctrl.Result {
	// Handle special errors that contribute to expressing the result.
	if e, ok := err.(*serror.Waiting); ok {
		return ctrl.Result{RequeueAfter: e.RequeueAfter}
	}

	switch rr {
	case ResultRequeue:
		return ctrl.Result{Requeue: true}
	case ResultSuccess:
		return ctrl.Result{RequeueAfter: successInterval}
	default:
		return ctrl.Result{}
	}
}

// RecordContextualError records the contextual errors based on their types.
// An event is recorded for the errors that are returned to the runtime. The
// runtime handles the logging of the error.
// An event is recorded and an error is logged for errors that are known to be
// swallowed, not returned to the runtime.
func RecordContextualError(ctx context.Context, recorder kuberecorder.EventRecorder, obj runtime.Object, err error) {
	switch e := err.(type) {
	case *serror.Event:
		recorder.Eventf(obj, corev1.EventTypeWarning, e.Reason, e.Error())
	case *serror.Waiting:
		// Waiting errors are not returned to the runtime. Log it explicitly.
		ctrl.LoggerFrom(ctx).Info("reconciliation waiting", "reason", e.Err, "duration", e.RequeueAfter)
		recorder.Event(obj, corev1.EventTypeNormal, e.Reason, e.Error())
	case *serror.Stalling:
		// Stalling errors are not returned to the runtime. Log it explicitly.
		ctrl.LoggerFrom(ctx).Error(e, "reconciliation stalled")
		recorder.Eventf(obj, corev1.EventTypeWarning, e.Reason, e.Error())
	}
}

// ComputeReconcileResult analyzes the reconcile results (result + error),
// updates the status conditions of the object with any corrections and returns
// object patch configuration, runtime result and runtime error. The caller is
// responsible for using the patch configuration to patch the object in the API
// server.
func ComputeReconcileResult(obj conditions.Setter, successInterval time.Duration, res Result, recErr error, ownedConditions []string) ([]patch.Option, ctrl.Result, error) {
	result := BuildRuntimeResult(successInterval, res, recErr)

	// Remove reconciling condition on successful reconciliation.
	if recErr == nil && res == ResultSuccess {
		conditions.Delete(obj, meta.ReconcilingCondition)
	}

	// Patch the object, ignoring conflicts on the conditions owned by this controller.
	pOpts := []patch.Option{
		patch.WithOwnedConditions{
			Conditions: ownedConditions,
		},
	}

	// Analyze the reconcile error.
	switch t := recErr.(type) {
	case *serror.Stalling:
		if res == ResultEmpty {
			// The current generation has been reconciled successfully and it
			// has resulted in a stalled state. Return no error to stop further
			// requeuing.
			pOpts = append(pOpts, patch.WithStatusObservedGeneration{})
			conditions.MarkStalled(obj, t.Reason, t.Error())
			return pOpts, result, nil
		}
		// NOTE: Non-empty result with stalling error indicates that the
		// returned result is incorrect.
	case *serror.Waiting:
		// The reconcile resulted in waiting error, remove stalled condition if
		// present.
		conditions.Delete(obj, meta.StalledCondition)
		// The reconciler needs to wait and retry. Return no error.
		return pOpts, result, nil
	case nil:
		// The reconcile didn't result in any error, we are not in stalled
		// state. If a requeue is requested, the current generation has not been
		// reconciled successfully.
		if res != ResultRequeue {
			pOpts = append(pOpts, patch.WithStatusObservedGeneration{})
		}
		conditions.Delete(obj, meta.StalledCondition)
	default:
		// The reconcile resulted in some error, but we are not in stalled
		// state.
		conditions.Delete(obj, meta.StalledCondition)
	}

	return pOpts, result, recErr
}

// LowestRequeuingResult returns the ReconcileResult with the lowest requeue
// period.
// Weightage:
//  ResultRequeue - immediate requeue (lowest)
//  ResultSuccess - requeue at an interval
//  ResultEmpty - no requeue
func LowestRequeuingResult(i, j Result) Result {
	switch {
	case i == ResultEmpty:
		return j
	case j == ResultEmpty:
		return i
	case i == ResultRequeue:
		return i
	case j == ResultRequeue:
		return j
	default:
		return j
	}
}
