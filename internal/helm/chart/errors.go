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
type BuildErrorReason struct {
	// Reason is the programmatic build error reason in CamelCase.
	Reason string

	// Summary is the human build error reason, used to provide
	// the Error string, and further context to the BuildError.
	Summary string
}

// Error returns the string representation of BuildErrorReason.
func (e BuildErrorReason) Error() string {
	return e.Summary
}

// BuildError contains a wrapped Err and a Reason indicating why it occurred.
type BuildError struct {
	Reason BuildErrorReason
	Err    error
}

// Error returns Err as a string, prefixed with the Reason to provide context.
func (e *BuildError) Error() string {
	if e.Reason.Error() == "" {
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
	if e.Reason == target {
		return true
	}
	return errors.Is(e.Err, target)
}

// Unwrap returns the underlying Err.
func (e *BuildError) Unwrap() error {
	return e.Err
}

func IsPersistentBuildErrorReason(err error) bool {
	switch err {
	case ErrChartReference, ErrChartMetadataPatch, ErrValuesFilesMerge:
		return true
	default:
		return false
	}
}

var (
	ErrChartReference     = BuildErrorReason{Reason: "InvalidChartReference", Summary: "invalid chart reference"}
	ErrChartPull          = BuildErrorReason{Reason: "ChartPullError", Summary: "chart pull error"}
	ErrChartMetadataPatch = BuildErrorReason{Reason: "MetadataPatchError", Summary: "chart metadata patch error"}
	ErrValuesFilesMerge   = BuildErrorReason{Reason: "ValuesFilesError", Summary: "values files merge error"}
	ErrDependencyBuild    = BuildErrorReason{Reason: "DependencyBuildError", Summary: "dependency build error"}
	ErrChartPackage       = BuildErrorReason{Reason: "ChartPackageError", Summary: "chart package error"}
	ErrUnknown            = BuildErrorReason{Reason: "Unknown", Summary: "unknown build error"}
)
