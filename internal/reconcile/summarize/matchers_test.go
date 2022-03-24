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
	"fmt"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/fluxcd/source-controller/internal/object"
)

// HaveStatusObservedGeneration returns a custom matcher to check if a
// runtime.Object has a given status observedGeneration value.
func HaveStatusObservedGeneration(expected int64) types.GomegaMatcher {
	return &haveStatusObservedGeneration{
		expected: expected,
	}
}

type haveStatusObservedGeneration struct {
	expected int64
	actual   int64
}

func (m *haveStatusObservedGeneration) Match(actual interface{}) (success bool, err error) {
	obj, ok := actual.(runtime.Object)
	if !ok {
		return false, fmt.Errorf("actual should be a runtime object")
	}

	og, err := object.GetStatusObservedGeneration(obj)
	if err != nil && err != object.ErrObservedGenerationNotFound {
		return false, err
	}
	m.actual = og

	return Equal(m.expected).Match(og)
}

func (m *haveStatusObservedGeneration) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%d\nto match\n\t%d\n", m.actual, m.expected)
}

func (m *haveStatusObservedGeneration) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%d\nto not match\n\t%d\n", m.actual, m.expected)
}

// HaveStatusLastHandledReconcileAt returns a custom matcher to check if a
// runtime.Object has a given status lastHandledReconcileAt value.
func HaveStatusLastHandledReconcileAt(expected string) types.GomegaMatcher {
	return &haveStatusLastHandledReconcileAt{
		expected: expected,
	}
}

type haveStatusLastHandledReconcileAt struct {
	expected string
	actual   string
}

func (m *haveStatusLastHandledReconcileAt) Match(actual interface{}) (success bool, err error) {
	obj, ok := actual.(runtime.Object)
	if !ok {
		return false, fmt.Errorf("actual should be a runtime object")
	}

	ra, err := object.GetStatusLastHandledReconcileAt(obj)
	if err != nil && err != object.ErrLastHandledReconcileAtNotFound {
		return false, err
	}
	m.actual = ra

	return Equal(m.expected).Match(ra)
}

func (m *haveStatusLastHandledReconcileAt) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%s\nto match\n\t%s\n", m.actual, m.expected)
}

func (m *haveStatusLastHandledReconcileAt) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%s\nto not match\n\t%s\n", m.actual, m.expected)
}
