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

package oci

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
)

// VerificationResult represents the result of a verification process.
type VerificationResult string

const (
	// VerificationResultSuccess indicates that the artifact has been verified.
	VerificationResultSuccess VerificationResult = "verified"
	// VerificationResultFailed indicates that the artifact could not be verified.
	VerificationResultFailed VerificationResult = "unverified"
	// VerificationResultIgnored indicates that the artifact has not been verified
	// but is allowed to proceed. This is used primarily when notation is used
	// as the verifier.
	VerificationResultIgnored VerificationResult = "ignored"
)

// Verifier is an interface for verifying the authenticity of an OCI image.
type Verifier interface {
	Verify(ctx context.Context, ref name.Reference) (VerificationResult, error)
}
