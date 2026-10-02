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

package reconcile

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/events"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// EventLogf records an event and logs the message at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
//
// The action identifies the reconcile stage that produced the event and is
// recorded in the event's action field. Callers pass the relevant
// sourcev1.Action for the stage.
func EventLogf(ctx context.Context, rec events.Recorder, obj runtime.Object, eventType string, reason string, action sourcev1.Action, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	rec.Eventf(obj, nil, eventType, reason, action.String(), "%s", msg)
}
