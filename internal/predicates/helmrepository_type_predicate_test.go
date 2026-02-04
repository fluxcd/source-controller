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

	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
)

func TestHelmRepositoryOCIMigrationPredicate_Create(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(o *sourcev1.HelmRepository)
		want       bool
	}{
		{
			name: "new oci helm repo no status",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Spec.Type = sourcev1.HelmRepositoryTypeOCI
			},
			want: false,
		},
		{
			name: "new oci helm repo with default observed gen status",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Spec.Type = sourcev1.HelmRepositoryTypeOCI
				o.Status.ObservedGeneration = -1
			},
			want: true,
		},
		{
			name: "old oci helm repo with finalizer only",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Finalizers = []string{sourcev1.SourceFinalizer}
				o.Spec.Type = sourcev1.HelmRepositoryTypeOCI
			},
			want: true,
		},
		{
			name: "old oci helm repo with status only",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Spec.Type = sourcev1.HelmRepositoryTypeOCI
				o.Status = sourcev1.HelmRepositoryStatus{
					ObservedGeneration: 3,
				}
				conditions.MarkTrue(o, meta.ReadyCondition, "foo", "bar")
			},
			want: true,
		},
		{
			name: "old oci helm repo with finalizer and status",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Finalizers = []string{sourcev1.SourceFinalizer}
				o.Spec.Type = sourcev1.HelmRepositoryTypeOCI
				o.Status = sourcev1.HelmRepositoryStatus{
					ObservedGeneration: 3,
				}
				conditions.MarkTrue(o, meta.ReadyCondition, "foo", "bar")
			},
			want: true,
		},
		{
			name: "new default helm repo",
			beforeFunc: func(o *sourcev1.HelmRepository) {
				o.Spec.Type = sourcev1.HelmRepositoryTypeDefault
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			o := &sourcev1.HelmRepository{}
			if tt.beforeFunc != nil {
				tt.beforeFunc(o)
			}
			e := event.CreateEvent{Object: o}
			p := HelmRepositoryOCIMigrationPredicate{}
			g.Expect(p.Create(e)).To(Equal(tt.want))
		})
	}
}

func TestHelmRepositoryOCIMigrationPredicate_Update(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(oldObj, newObj *sourcev1.HelmRepository)
		want       bool
	}{
		{
			name: "update oci repo",
			beforeFunc: func(oldObj, newObj *sourcev1.HelmRepository) {
				oldObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeOCI,
					URL:  "oci://foo/bar",
				}
				*newObj = *oldObj.DeepCopy()
				newObj.Spec.URL = "oci://foo/baz"
			},
			want: false,
		},
		{
			name: "migrate old oci repo with status only",
			beforeFunc: func(oldObj, newObj *sourcev1.HelmRepository) {
				oldObj.Generation = 2
				oldObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeOCI,
				}
				oldObj.Status = sourcev1.HelmRepositoryStatus{
					ObservedGeneration: 2,
				}
				conditions.MarkTrue(oldObj, meta.ReadyCondition, "foo", "bar")

				*newObj = *oldObj.DeepCopy()
				newObj.Generation = 3
			},
			want: true,
		},
		{
			name: "migrate old oci repo with finalizer only",
			beforeFunc: func(oldObj, newObj *sourcev1.HelmRepository) {
				oldObj.Generation = 2
				oldObj.Finalizers = []string{sourcev1.SourceFinalizer}
				oldObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeOCI,
				}

				*newObj = *oldObj.DeepCopy()
				newObj.Generation = 3
			},
			want: true,
		},
		{
			name: "type switch default to oci",
			beforeFunc: func(oldObj, newObj *sourcev1.HelmRepository) {
				oldObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeDefault,
				}
				oldObj.Status = sourcev1.HelmRepositoryStatus{
					Artifact:           &meta.Artifact{},
					URL:                "http://some-address",
					ObservedGeneration: 3,
				}

				*newObj = *oldObj.DeepCopy()
				newObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeOCI,
				}
			},
			want: true,
		},
		{
			name: "type switch oci to default",
			beforeFunc: func(oldObj, newObj *sourcev1.HelmRepository) {
				oldObj.Spec = sourcev1.HelmRepositorySpec{
					Type: sourcev1.HelmRepositoryTypeOCI,
				}
				*newObj = *oldObj.DeepCopy()
				newObj.Spec.Type = sourcev1.HelmRepositoryTypeDefault
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			oldObj := &sourcev1.HelmRepository{}
			newObj := oldObj.DeepCopy()
			if tt.beforeFunc != nil {
				tt.beforeFunc(oldObj, newObj)
			}
			e := event.UpdateEvent{
				ObjectOld: oldObj,
				ObjectNew: newObj,
			}
			p := HelmRepositoryOCIMigrationPredicate{}
			g.Expect(p.Update(e)).To(Equal(tt.want))
		})
	}
}

func TestHelmRepositoryOCIMigrationPredicate_Delete(t *testing.T) {
	tests := []struct {
		name       string
		beforeFunc func(obj *sourcev1.HelmRepository)
		want       bool
	}{
		{
			name: "oci with finalizer",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Finalizers = []string{sourcev1.SourceFinalizer}
				obj.Spec.Type = sourcev1.HelmRepositoryTypeOCI
			},
			want: true,
		},
		{
			name: "oci with status",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.Type = sourcev1.HelmRepositoryTypeOCI
				obj.Status.ObservedGeneration = 4
			},
			want: true,
		},
		{
			name: "oci without finalizer or status",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.Type = sourcev1.HelmRepositoryTypeOCI
			},
			want: false,
		},
		{
			name: "default helm repo",
			beforeFunc: func(obj *sourcev1.HelmRepository) {
				obj.Spec.Type = sourcev1.HelmRepositoryTypeDefault
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.HelmRepository{}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}
			e := event.DeleteEvent{Object: obj}
			p := HelmRepositoryOCIMigrationPredicate{}
			g.Expect(p.Delete(e)).To(Equal(tt.want))
		})
	}
}
