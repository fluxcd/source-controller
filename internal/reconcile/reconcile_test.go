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

package reconcile

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestLowestRequeuingResult(t *testing.T) {
	tests := []struct {
		name       string
		i          Result
		j          Result
		wantResult Result
	}{
		{"bail,requeue", ResultEmpty, ResultRequeue, ResultRequeue},
		{"bail,requeueInterval", ResultEmpty, ResultSuccess, ResultSuccess},
		{"requeue,bail", ResultRequeue, ResultEmpty, ResultRequeue},
		{"requeue,requeueInterval", ResultRequeue, ResultSuccess, ResultRequeue},
		{"requeueInterval,requeue", ResultSuccess, ResultRequeue, ResultRequeue},
		{"requeueInterval,requeueInterval", ResultSuccess, ResultSuccess, ResultSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(LowestRequeuingResult(tt.i, tt.j)).To(Equal(tt.wantResult))
		})
	}
}
