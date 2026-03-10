/*
Copyright 2026 The Flux authors

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
	"context"
	"testing"

	"github.com/fluxcd/pkg/apis/meta"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadTrustedRootFromSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name      string
		namespace string
		ref       *meta.LocalObjectReference
		secret    *corev1.Secret
		wantData  []byte
		wantErr   string
	}{
		{
			name:      "reads trusted_root.json from secret",
			namespace: "default",
			ref:       &meta.LocalObjectReference{Name: "sigstore-root"},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sigstore-root",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"trusted_root.json": []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`),
				},
			},
			wantData: []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`),
		},
		{
			name:      "error when secret does not exist",
			namespace: "default",
			ref:       &meta.LocalObjectReference{Name: "missing-secret"},
			wantErr:   `"missing-secret" not found`,
		},
		{
			name:      "error when key is missing from secret",
			namespace: "default",
			ref:       &meta.LocalObjectReference{Name: "no-key-secret"},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"other-key": []byte("data"),
				},
			},
			wantErr: "'trusted_root.json' not found in secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.secret != nil {
				builder = builder.WithObjects(tt.secret)
			}
			c := builder.Build()

			data, err := readTrustedRootFromSecret(context.Background(), c, tt.namespace, tt.ref)

			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(data).To(Equal(tt.wantData))
		})
	}
}
