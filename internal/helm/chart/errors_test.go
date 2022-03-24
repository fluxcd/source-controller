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
	"testing"

	. "github.com/onsi/gomega"
)

func TestBuildErrorReason_Error(t *testing.T) {
	g := NewWithT(t)

	err := BuildErrorReason{"Reason", "reason"}
	g.Expect(err.Error()).To(Equal("reason"))
}

func TestBuildError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *BuildError
		want string
	}{
		{
			name: "with reason",
			err: &BuildError{
				Reason: BuildErrorReason{"Reason", "reason"},
				Err:    errors.New("error"),
			},
			want: "reason: error",
		},
		{
			name: "without reason",
			err: &BuildError{
				Err: errors.New("error"),
			},
			want: "error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tt.err.Error()).To(Equal(tt.want))
		})
	}
}

func TestBuildError_Is(t *testing.T) {
	g := NewWithT(t)

	wrappedErr := errors.New("wrapped")
	err := &BuildError{
		Reason: ErrChartPackage,
		Err:    wrappedErr,
	}

	g.Expect(err.Is(ErrChartPackage)).To(BeTrue())
	g.Expect(err.Is(wrappedErr)).To(BeTrue())
	g.Expect(err.Is(ErrDependencyBuild)).To(BeFalse())
}

func TestBuildError_Unwrap(t *testing.T) {
	g := NewWithT(t)

	wrap := errors.New("wrapped")
	err := BuildError{Err: wrap}
	g.Expect(err.Unwrap()).To(Equal(wrap))
}
