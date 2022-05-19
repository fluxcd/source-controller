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

package predicates

import (
	"testing"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestHelmRepositoryTypePredicate_Create(t *testing.T) {
	obj := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{}}
	http := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{Type: "default"}}
	oci := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{Type: "oci"}}
	not := &unstructured.Unstructured{}

	tests := []struct {
		name string
		obj  client.Object
		want bool
	}{
		{name: "new", obj: obj, want: false},
		{name: "http", obj: http, want: true},
		{name: "oci", obj: oci, want: false},
		{name: "not a HelmRepository", obj: not, want: false},
		{name: "nil", obj: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			so := HelmRepositoryTypePredicate{RepositoryType: "default"}
			e := event.CreateEvent{
				Object: tt.obj,
			}
			g.Expect(so.Create(e)).To(gomega.Equal(tt.want))
		})
	}
}

func TestHelmRepositoryTypePredicate_Update(t *testing.T) {
	repoA := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{
		Type: sourcev1.HelmRepositoryTypeDefault,
	}}

	repoB := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{
		Type: sourcev1.HelmRepositoryTypeOCI,
	}}

	empty := &sourcev1.HelmRepository{}
	not := &unstructured.Unstructured{}

	tests := []struct {
		name string
		old  client.Object
		new  client.Object
		want bool
	}{
		{name: "diff type", old: repoA, new: repoB, want: true},
		{name: "new with type", old: empty, new: repoA, want: true},
		{name: "old with type", old: repoA, new: empty, want: true},
		{name: "old not a HelmRepository", old: not, new: repoA, want: false},
		{name: "new not a HelmRepository", old: repoA, new: not, want: false},
		{name: "old nil", old: nil, new: repoA, want: false},
		{name: "new nil", old: repoA, new: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			so := HelmRepositoryTypePredicate{RepositoryType: "default"}
			e := event.UpdateEvent{
				ObjectOld: tt.old,
				ObjectNew: tt.new,
			}
			g.Expect(so.Update(e)).To(gomega.Equal(tt.want))
		})
	}
}

func TestHelmRepositoryTypePredicate_Delete(t *testing.T) {
	obj := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{}}
	http := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{Type: "default"}}
	oci := &sourcev1.HelmRepository{Spec: sourcev1.HelmRepositorySpec{Type: "oci"}}
	not := &unstructured.Unstructured{}

	tests := []struct {
		name string
		obj  client.Object
		want bool
	}{
		{name: "new", obj: obj, want: false},
		{name: "http", obj: http, want: true},
		{name: "oci", obj: oci, want: false},
		{name: "not a HelmRepository", obj: not, want: false},
		{name: "nil", obj: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			so := HelmRepositoryTypePredicate{RepositoryType: "default"}
			e := event.DeleteEvent{
				Object: tt.obj,
			}
			g.Expect(so.Delete(e)).To(gomega.Equal(tt.want))
		})
	}
}
