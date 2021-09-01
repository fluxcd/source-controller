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

package gcp

import (
	"context"
	"testing"

	"gotest.tools/assert"
)

func TestSetRange(t *testing.T) {
	client, err := NewClient(context.Background())
	assert.NilError(t, err)
	testCases := []struct {
		title string
		start int64
		end   int64
	}{
		{
			title: "Test Case 1",
			start: 1,
			end:   5,
		},
		{
			title: "Test Case 2",
			start: 3,
			end:   6,
		},
		{
			title: "Test Case 3",
			start: 4,
			end:   5,
		},
		{
			title: "Test Case 4",
			start: 2,
			end:   7,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.title, func(t *testing.T) {
			client.SetRange(tt.start, tt.end)
			assert.Equal(t, tt.start, client.startRange)
			assert.Equal(t, tt.end, client.endRange)
		})
	}
}
