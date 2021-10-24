/*
Copyright 2020 The Flux authors

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

package strategy

import (
	"context"
	"fmt"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
)

// CheckoutStrategyForImplementation returns the CheckoutStrategy for the given
// git.Implementation and git.CheckoutOptions.
func CheckoutStrategyForImplementation(ctx context.Context, impl git.Implementation, opts git.CheckoutOptions) (git.CheckoutStrategy, error) {
	switch impl {
	case gogit.Implementation:
		return gogit.CheckoutStrategyForOptions(ctx, opts), nil
	case libgit2.Implementation:
		return libgit2.CheckoutStrategyForOptions(ctx, opts), nil
	default:
		return nil, fmt.Errorf("unsupported Git implementation '%s'", impl)
	}
}
