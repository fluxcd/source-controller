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

package util

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestTempDirForObj(t *testing.T) {
	g := NewWithT(t)

	got, err := TempDirForObj("", mockObj())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(BeADirectory())
	defer os.RemoveAll(got)

	got2, err := TempDirForObj(got, mockObj())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got2).To(BeADirectory())
	defer os.RemoveAll(got2)
	g.Expect(got2).To(ContainSubstring(got))
}

func TestTempPathForObj(t *testing.T) {
	tests := []struct {
		name   string
		dir    string
		suffix string
		want   string
	}{
		{
			name: "default",
			want: filepath.Join(os.TempDir(), "secret-default-foo-"),
		},
		{
			name: "with directory",
			dir:  "/foo",
			want: "/foo/secret-default-foo-",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got := TempPathForObj(tt.dir, tt.suffix, mockObj())
			g.Expect(got[:len(got)-32]).To(Equal(tt.want))
		})
	}
}

func Test_pattern(t *testing.T) {
	g := NewWithT(t)
	g.Expect(pattern(mockObj())).To(Equal("secret-default-foo-"))
}

func mockObj() client.Object {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind: "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
	}
}
