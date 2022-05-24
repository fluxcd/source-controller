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

package error

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// EventTypeNone indicates no error event. It can be used to disable error
// events.
const EventTypeNone = "None"

// Config is the error configuration. It is embedded in the errors and can be
// used to configure how the error should be handled. These configurations
// mostly define actions to be taken on the errors. Not all the configurations
// may apply to every error.
type Config struct {
	// Event is the event type of an error. It is used to configure what type of
	// event an error should result in.
	// Valid values:
	//   - EventTypeNone
	//   - corev1.EventTypeNormal
	//   - corev1.EventTypeWarning
	Event string
	// Log is used to configure if an error should be logged. The log level is
	// derived from the Event type.
	// None event - info log
	// Normal event - info log
	// Warning event - error log
	Log bool
	// Notification is used to emit an error as a notification alert to a
	// a notification service.
	Notification bool
	// Ignore is used to suppress the error for no-op reconciliations. It may
	// be applicable to non-contextual errors only.
	Ignore bool
}

// Stalling is the reconciliation stalled state error. It contains an error
// and a reason for the stalled condition. It is a contextual error, used to
// express the scenario which contributed to the reconciliation result.
type Stalling struct {
	// Reason is the stalled condition reason string.
	Reason string
	// Err is the error that caused stalling. This can be used as the message in
	// stalled condition.
	Err error
	// Config is the error handler configuration.
	Config
}

// Error implements error interface.
func (se *Stalling) Error() string {
	return se.Err.Error()
}

// Unwrap returns the underlying error.
func (se *Stalling) Unwrap() error {
	return se.Err
}

// NewStalling constructs a new Stalling error with default configuration.
func NewStalling(err error, reason string) *Stalling {
	// Stalling errors are not returned to the runtime. Log it explicitly.
	// Since this failure requires user interaction, send warning notification.
	return &Stalling{
		Reason: reason,
		Err:    err,
		Config: Config{
			Event:        corev1.EventTypeWarning,
			Log:          true,
			Notification: true,
		},
	}
}

// Event is an error event. It can be used to construct an event to be
// recorded.
// Deprecated: use Generic error with NewGeneric() for the same behavior and
// replace the RecordContextualError with ErrorActionHandler for result
// processing.
type Event struct {
	// Reason is the reason for the event error.
	Reason string
	// Error is the actual error for the event.
	Err error
}

// Error implements error interface.
func (ee *Event) Error() string {
	return ee.Err.Error()
}

// Unwrap returns the underlying error.
func (ee *Event) Unwrap() error {
	return ee.Err
}

// Waiting is the reconciliation wait state error. It contains an error, wait
// duration and a reason for the wait. It is a contextual error, used to express
// the scenario which contributed to the reconciliation result.
// It is for scenarios where a reconciliation needs to wait for something else
// to take place first.
type Waiting struct {
	// RequeueAfter is the wait duration after which to requeue.
	RequeueAfter time.Duration
	// Reason is the reason for the wait.
	Reason string
	// Err is the error that caused the wait.
	Err error
	// Config is the error handler configuration.
	Config
}

// Error implements error interface.
func (we *Waiting) Error() string {
	return we.Err.Error()
}

// Unwrap returns the underlying error.
func (we *Waiting) Unwrap() error {
	return we.Err
}

// NewWaiting constructs a new Waiting error with default configuration.
func NewWaiting(err error, reason string) *Waiting {
	// Waiting errors are not returned to the runtime. Log it explicitly.
	// Since this failure results in reconciliation delay, send warning
	// notification.
	return &Waiting{
		Reason: reason,
		Err:    err,
		Config: Config{
			Event: corev1.EventTypeNormal,
			Log:   true,
		},
	}
}

// Generic error is a generic reconcile error. It can be used in scenarios that
// don't have any special contextual meaning.
type Generic struct {
	// Reason is the reason for the generic error.
	Reason string
	// Error is the error that caused the generic error.
	Err error
	// Config is the error handler configuration.
	Config
}

// Error implements error interface.
func (g *Generic) Error() string {
	return g.Err.Error()
}

// Unwrap returns the underlying error.
func (g *Generic) Unwrap() error {
	return g.Err
}

// NewGeneric constructs a new Generic error with default configuration.
func NewGeneric(err error, reason string) *Generic {
	// Since it's a error, ensure to log and send failure notification.
	return &Generic{
		Reason: reason,
		Err:    err,
		Config: Config{
			Event:        corev1.EventTypeWarning,
			Log:          true,
			Notification: true,
		},
	}
}
