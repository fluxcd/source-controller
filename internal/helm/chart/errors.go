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

package chart

import (
	"errors"
	"fmt"
)

// BuildErrorReason is the descriptive reason for a BuildError.
type BuildErrorReason string

// Error returns the string representation of BuildErrorReason.
func (e BuildErrorReason) Error() string {
	return string(e)
}

// BuildError contains a wrapped Err and a Reason indicating why it occurred.
type BuildError struct {
	Reason error
	Err    error
}

// Error returns Err as a string, prefixed with the Reason to provide context.
func (e *BuildError) Error() string {
	if e.Reason == nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %s", e.Reason.Error(), e.Err.Error())
}

// Is returns true if the Reason or Err equals target.
// It can be used to programmatically place an arbitrary Err in the
// context of the Builder:
//  err := &BuildError{Reason: ErrChartPull, Err: errors.New("arbitrary transport error")}
//  errors.Is(err, ErrChartPull)
func (e *BuildError) Is(target error) bool {
	if e.Reason != nil && e.Reason == target {
		return true
	}
	return errors.Is(e.Err, target)
}

// Unwrap returns the underlying Err.
func (e *BuildError) Unwrap() error {
	return e.Err
}

var (
	ErrChartReference     = BuildErrorReason("chart reference error")
	ErrChartPull          = BuildErrorReason("chart pull error")
	ErrChartMetadataPatch = BuildErrorReason("chart metadata patch error")
	ErrValuesFilesMerge   = BuildErrorReason("values files merge error")
	ErrDependencyBuild    = BuildErrorReason("dependency build error")
	ErrChartPackage       = BuildErrorReason("chart package error")
)
