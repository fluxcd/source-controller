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

package managed

import (
	"os"
	"testing"
)

func TestFlagStatus(t *testing.T) {
	if Enabled() {
		t.Errorf("experimental transport should not be enabled by default")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "true")
	if !Enabled() {
		t.Errorf("experimental transport should be enabled when env EXPERIMENTAL_GIT_TRANSPORT=true")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "1")
	if !Enabled() {
		t.Errorf("experimental transport should be enabled when env EXPERIMENTAL_GIT_TRANSPORT=1")
	}

	os.Setenv("EXPERIMENTAL_GIT_TRANSPORT", "somethingelse")
	if Enabled() {
		t.Errorf("experimental transport should be enabled only when env EXPERIMENTAL_GIT_TRANSPORT is 1 or true but was enabled for 'somethingelse'")
	}

	os.Unsetenv("EXPERIMENTAL_GIT_TRANSPORT")
	if Enabled() {
		t.Errorf("experimental transport should not be enabled when env EXPERIMENTAL_GIT_TRANSPORT is not present")
	}
}
