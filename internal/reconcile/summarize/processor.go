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
	"strings"

	corev1 "k8s.io/api/core/v1"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/object"
	"github.com/fluxcd/source-controller/internal/reconcile"
)

// ResultProcessor processes the results of reconciliation (the object, result
// and error). Any errors during processing need not result in the
// reconciliation failure. The errors can be recorded as logs and events.
type ResultProcessor func(context.Context, kuberecorder.EventRecorder, conditions.Setter, reconcile.Result, error)

// RecordContextualError is a ResultProcessor that records the contextual errors
// based on their types.
// An event is recorded for the errors that are returned to the runtime. The
// runtime handles the logging of the error.
// An event is recorded and an error is logged for errors that are known to be
// swallowed, not returned to the runtime.
func RecordContextualError(ctx context.Context, recorder kuberecorder.EventRecorder, obj conditions.Setter, _ reconcile.Result, err error) {
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

// RecordReconcileReq is a ResultProcessor that checks the reconcile
// annotation value and sets it in the object status as
// status.lastHandledReconcileAt.
func RecordReconcileReq(ctx context.Context, recorder kuberecorder.EventRecorder, obj conditions.Setter, _ reconcile.Result, _ error) {
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		object.SetStatusLastHandledReconcileAt(obj, v)
	}
}

// NotifySuccess returns a ResultProcessor that emits success event based on the
// reconciliation results. It takes an old version of the target object, a
// Notification and fail conditions to analyze the result of reconciliation and
// create an event. In order to emit unique events, it suppresses recovery event
// if the success notification is not empty. If there's no success notification,
// but a recovery from a failure, only the recovery message is emitted as an
// event. This helps create events that are informational to the notification
// service and useful as Kubernetes native events with event counter for similar
// events.
func NotifySuccess(oldObj conditions.Setter, n Notification, failConditions []string) ResultProcessor {
	return func(ctx context.Context, recorder kuberecorder.EventRecorder, obj conditions.Setter, result reconcile.Result, err error) {
		if err == nil && result == reconcile.ResultSuccess {
			var annotations map[string]string
			reason := meta.SucceededReason
			messages := []string{}

			// Check the old object status conditions to determine if there was
			// a recovery from some failure.
			for _, failCondition := range failConditions {
				oldFailedCondition := conditions.Get(oldObj, failCondition)
				if oldFailedCondition != nil && conditions.Get(obj, failCondition) == nil {
					messages = append(messages, fmt.Sprintf("resolved '%s'", oldFailedCondition.Reason))
				}
			}

			// Populate event metadata from the new artifact notification,
			// suppressing previous information.
			if !n.IsZero() {
				annotations = n.Annotations
				reason = n.Reason
				messages = []string{n.Message}
			}

			// No event if there's no message.
			if len(messages) > 0 {
				recorder.AnnotatedEventf(obj, annotations, corev1.EventTypeNormal, reason, strings.Join(messages, ", "))
			}
		}
	}
}
