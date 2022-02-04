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

package object

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

func TestGetStatusLastHandledReconcileAt(t *testing.T) {
	g := NewWithT(t)

	// Get unset status lastHandledReconcileAt.
	obj := &sourcev1.GitRepository{}
	_, err := GetStatusLastHandledReconcileAt(obj)
	g.Expect(err).To(Equal(ErrLastHandledReconcileAtNotFound))

	// Get set status lastHandledReconcileAt.
	obj.Status.LastHandledReconcileAt = "foo"
	ra, err := GetStatusLastHandledReconcileAt(obj)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ra).To(Equal("foo"))
}

func TestSetStatusLastHandledReconcileAt(t *testing.T) {
	g := NewWithT(t)

	obj := &sourcev1.GitRepository{}
	err := SetStatusLastHandledReconcileAt(obj, "now")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(obj.Status.LastHandledReconcileAt).To(Equal("now"))
}

func TestGetStatusObservedGeneration(t *testing.T) {
	g := NewWithT(t)

	// Get unset status observedGeneration.
	obj := &sourcev1.GitRepository{}
	_, err := GetStatusObservedGeneration(obj)
	g.Expect(err).To(Equal(ErrObservedGenerationNotFound))

	// Get set status observedGeneration.
	obj.Status.ObservedGeneration = 7
	og, err := GetStatusObservedGeneration(obj)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(og).To(Equal(int64(7)))
}

func TestGetRequeueInterval(t *testing.T) {
	g := NewWithT(t)

	// Get empty requeue interval value.
	obj := &sourcev1.GitRepository{}
	pd, err := GetRequeueInterval(obj)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(pd).To(Equal(time.Duration(0)))

	// Get set requeue interval value.
	obj.Spec.Interval = metav1.Duration{Duration: 3 * time.Second}
	pd, err = GetRequeueInterval(obj)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(pd).To(Equal(3 * time.Second))

	// Get non-existent requeue interval value.
	obj2 := &corev1.Secret{}
	_, err = GetRequeueInterval(obj2)
	g.Expect(err).To(Equal(ErrRequeueIntervalNotFound))
}
