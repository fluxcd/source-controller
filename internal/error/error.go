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

// StallingError is the reconciliation stalled state error. It contains an error
// and a reason for the stalled condition.
type StallingError struct {
	// Reason is the stalled condition reason string.
	Reason string
	// Err is the error that caused stalling. This can be used as the message in
	// stalled condition.
	Err error
}

// Error implements error interface.
func (se *StallingError) Error() string {
	return se.Err.Error()
}

// Unwrap returns the underlying error.
func (se *StallingError) Unwrap() error {
	return se.Err
}
