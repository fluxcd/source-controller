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

package controllers

import (
	"fmt"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

// MatchArtifact returns a custom matcher to check equality of a v1beta1.Artifact, the timestamp and URL are ignored.
func MatchArtifact(expected *sourcev1.Artifact) types.GomegaMatcher {
	return &matchArtifact{
		expected: expected,
	}
}

type matchArtifact struct {
	expected *sourcev1.Artifact
}

func (m matchArtifact) Match(actual interface{}) (success bool, err error) {
	actualArtifact, ok := actual.(*sourcev1.Artifact)
	if !ok {
		return false, fmt.Errorf("actual should be a pointer to an Artifact")
	}

	if ok, _ := BeNil().Match(m.expected); ok {
		return BeNil().Match(actual)
	}

	if ok, err = Equal(m.expected.Path).Match(actualArtifact.Path); !ok {
		return ok, err
	}
	if ok, err = Equal(m.expected.Revision).Match(actualArtifact.Revision); !ok {
		return ok, err
	}
	if ok, err = Equal(m.expected.Checksum).Match(actualArtifact.Checksum); !ok {
		return ok, err
	}

	return ok, err
}

func (m matchArtifact) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%#v\nto match\n\t%#v\n", actual, m.expected)
}

func (m matchArtifact) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("expected\n\t%#v\nto not match\n\t%#v\n", actual, m.expected)
}
