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

// This file is named `managed_checkout_test.go` on purpose to make sure that
// tests needing to use unmanaged transports run before the tests that use managed
// transports do, since the the former are present in `checkout_test.go`. `checkout_test.go`
// comes first in this package (alphabetically speaking), which makes golang run the tests
// in that file first.
package libgit2

import (
	"testing"
)

func TestCheckoutBranch_CheckoutManaged(t *testing.T) {
	enableManagedTransport()
	checkoutBranch(t, true)
}

func TestCheckoutTag_CheckoutManaged(t *testing.T) {
	enableManagedTransport()
	checkoutTag(t, true)
}

func TestCheckoutCommit_CheckoutManaged(t *testing.T) {
	enableManagedTransport()
	checkoutCommit(t, true)
}

func TestCheckoutTagSemVer_CheckoutManaged(t *testing.T) {
	enableManagedTransport()
	checkoutSemVer(t, true)
}
