/*
Copyright 2020 The Flux CD contributors.

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
	"os"
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/testserver"
)

var _ = Describe("HelmChartReconciler", func() {

	const (
		timeout       = time.Second * 30
		interval      = time.Second * 1
		indexInterval = time.Second * 2
		pullInterval  = time.Second * 3
	)

	Context("HelmChart", func() {
		var (
			namespace  *corev1.Namespace
			helmServer *testserver.Helm
			err        error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "helm-chart-test" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			helmServer, err = testserver.NewTempHelmServer()
			Expect(err).To(Succeed())
			helmServer.Start()
		})

		AfterEach(func() {
			os.RemoveAll(helmServer.Root())
			helmServer.Stop()

			err = k8sClient.Delete(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
		})

		It("Creates artifacts for", func() {
			Expect(helmServer.PackageChart(path.Join("testdata/helmchart"))).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			repositoryKey := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			Expect(k8sClient.Create(context.Background(), &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repositoryKey.Name,
					Namespace: repositoryKey.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      helmServer.URL(),
					Interval: metav1.Duration{Duration: indexInterval},
				},
			})).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmchart-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmChartSpec{
					Name:              "helmchart",
					Version:           "*",
					HelmRepositoryRef: corev1.LocalObjectReference{Name: repositoryKey.Name},
					Interval:          metav1.Duration{Duration: pullInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			By("Expecting artifact")
			got := &sourcev1.HelmChart{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil && storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Packaging a new chart version and regenerating the index")
			Expect(helmServer.PackageChartWithVersion(path.Join("testdata/helmchart"), "0.2.0")).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			By("Expecting new artifact revision and GC")
			Eventually(func() bool {
				now := &sourcev1.HelmChart{}
				_ = k8sClient.Get(context.Background(), key, now)
				// Test revision change and garbage collection
				return now.Status.Artifact.Revision != got.Status.Artifact.Revision &&
					!storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Expecting to delete successfully")
			got = &sourcev1.HelmChart{}
			Eventually(func() error {
				_ = k8sClient.Get(context.Background(), key, got)
				return k8sClient.Delete(context.Background(), got)
			}, timeout, interval).Should(Succeed())

			By("Expecting delete to finish")
			Eventually(func() error {
				c := &sourcev1.HelmChart{}
				return k8sClient.Get(context.Background(), key, c)
			}).ShouldNot(Succeed())

			By("Expecting GC on delete")
			Eventually(storage.ArtifactExist(*got.Status.Artifact), timeout, interval).ShouldNot(BeTrue())
		})

		It("Filters versions", func() {
			versions := []string{"0.1.0", "0.1.1", "0.2.0", "0.3.0-rc.1", "1.0.0-alpha.1", "1.0.0"}
			for k := range versions {
				Expect(helmServer.PackageChartWithVersion(path.Join("testdata/helmchart"), versions[k])).Should(Succeed())
			}

			Expect(helmServer.GenerateIndex()).Should(Succeed())

			repositoryKey := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			Expect(k8sClient.Create(context.Background(), &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repositoryKey.Name,
					Namespace: repositoryKey.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      helmServer.URL(),
					Interval: metav1.Duration{Duration: 1 * time.Hour},
				},
			})).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmchart-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			chart := &sourcev1.HelmChart{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmChartSpec{
					Name:              "helmchart",
					Version:           "*",
					HelmRepositoryRef: corev1.LocalObjectReference{Name: repositoryKey.Name},
					Interval:          metav1.Duration{Duration: 1 * time.Hour},
				},
			}
			Expect(k8sClient.Create(context.Background(), chart)).Should(Succeed())

			Eventually(func() string {
				_ = k8sClient.Get(context.Background(), key, chart)
				if chart.Status.Artifact != nil {
					return chart.Status.Artifact.Revision
				}
				return ""
			}, timeout, interval).Should(Equal("1.0.0"))

			chart.Spec.Version = "~0.1.0"
			Expect(k8sClient.Update(context.Background(), chart)).Should(Succeed())
			Eventually(func() string {
				_ = k8sClient.Get(context.Background(), key, chart)
				if chart.Status.Artifact != nil {
					return chart.Status.Artifact.Revision
				}
				return ""
			}, timeout, interval).Should(Equal("0.1.1"))

			chart.Spec.Version = "invalid"
			Expect(k8sClient.Update(context.Background(), chart)).Should(Succeed())
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, chart)
				for _, c := range chart.Status.Conditions {
					if c.Reason == sourcev1.ChartPullFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(chart.Status.Artifact.Revision).Should(Equal("0.1.1"))
		})
	})
})
