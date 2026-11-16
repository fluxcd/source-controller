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

package controller

import (
	"github.com/fluxcd/pkg/apis/meta"
)

type artifactSet []*meta.Artifact

// Diff returns true if the revisions in the artifactSet do not match those of
// the given set, regardless of order. A revision that appears more than once
// must appear the same number of times in both sets, otherwise a change in a
// set that holds duplicate revisions goes unnoticed.
func (s artifactSet) Diff(set artifactSet) bool {
	if len(s) != len(set) {
		return true
	}

	counts := make(map[string]int, len(set))
	for _, k := range set {
		counts[k.Revision]++
	}
	for _, j := range s {
		if counts[j.Revision] == 0 {
			return true
		}
		counts[j.Revision]--
	}
	return false
}
