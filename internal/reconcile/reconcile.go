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
	ctrl "sigs.k8s.io/controller-runtime"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
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
func BuildRuntimeResult(obj sourcev1.Source, rr Result, err error) (ctrl.Result, error) {
	// NOTE: The return values can be modified based on the error type.
	// For example, if an error signifies a short requeue period that's
	// not equal to the requeue period of the object, the error can be checked
	// and an appropriate result with the period can be returned.
	//
	// Example:
	//  if e, ok := err.(*waitError); ok {
	//	  return ctrl.Result{RequeueAfter: e.RequeueAfter}, err
	//  }

	switch rr {
	case ResultRequeue:
		return ctrl.Result{Requeue: true}, err
	case ResultSuccess:
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, err
	default:
		return ctrl.Result{}, err
	}
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
