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

package controllers

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/kinvolk/go-omaha/omaha"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("OmahaReconciler", func() {

	const (
		timeout           = time.Second * 30
		interval          = time.Second * 1
		indexInterval     = time.Second * 2
		repositoryTimeout = time.Second * 5
	)

	Context("Omaha", func() {
		var (
			namespace   *corev1.Namespace
			omahaServer *omaha.TrivialServer
			err         error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "omaha-repository-" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			omahaServer, err = omaha.NewTrivialServer("127.0.0.1:0")
			Expect(err).To(Succeed())
		})

		AfterEach(func() {
			Expect(omahaServer.Destroy()).Should(Succeed())
			// os.RemoveAll(omahaServer.Root())

			Eventually(func() error {
				return k8sClient.Delete(context.Background(), namespace)
			}, timeout, interval).Should(Succeed(), "failed to delete test namespace")
		})

		It("Creates artifacts for", func() {
			omahaServer.SetVersion("1.2.3")
			Expect(omahaServer.AddPackage(path.Join("testdata/charts/helmchart-0.1.0.tgz"), "app")).Should(Succeed())

			go omahaServer.Serve()

			key := types.NamespacedName{
				Name:      "omaha-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.Omaha{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.OmahaSpec{
					URL:      fmt.Sprintf("http://%s", omahaServer.Addr().String()),
					Interval: metav1.Duration{Duration: indexInterval},
					AppID:    "app",
					// Timeout:  &metav1.Duration{Duration: repositoryTimeout},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			By("Expecting artifact")
			got := &sourcev1.Omaha{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil && storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Expecting revision change and GC")
			omahaServer.SetVersion("1.2.4")

			Eventually(func() bool {
				now := &sourcev1.Omaha{}
				_ = k8sClient.Get(context.Background(), key, now)
				// Test revision change and garbage collection
				return now.Status.Artifact != nil && now.Status.Artifact.Revision != got.Status.Artifact.Revision &&
					!storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			updated := &sourcev1.Omaha{}
			Expect(k8sClient.Get(context.Background(), key, updated)).Should(Succeed())
			updated.Spec.URL = "invalid#url?"
			Expect(k8sClient.Update(context.Background(), updated)).Should(Succeed())
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, updated)
				for _, c := range updated.Status.Conditions {
					if c.Reason == sourcev1.URLInvalidReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(updated.Status.Artifact).ToNot(BeNil())

			By("Expecting to delete successfully")
			got = &sourcev1.Omaha{}
			Eventually(func() error {
				_ = k8sClient.Get(context.Background(), key, got)
				return k8sClient.Delete(context.Background(), got)
			}, timeout, interval).Should(Succeed())

			By("Expecting delete to finish")
			Eventually(func() error {
				r := &sourcev1.Omaha{}
				return k8sClient.Get(context.Background(), key, r)
			}, timeout, interval).ShouldNot(Succeed())

			exists := func(path string) bool {
				// wait for tmp sync on macOS
				time.Sleep(time.Second)
				_, err := os.Stat(path)
				return err == nil
			}

			By("Expecting GC after delete")
			Eventually(exists(got.Status.Artifact.Path), timeout, interval).ShouldNot(BeTrue())
		})
	})
})
