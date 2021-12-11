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
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/helmtestserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

var _ = Describe("HelmRepositoryReconciler", func() {

	const (
		timeout           = time.Second * 30
		interval          = time.Second * 1
		indexInterval     = time.Second * 2
		repositoryTimeout = time.Second * 5
	)

	Context("HelmRepository", func() {
		var (
			namespace  *corev1.Namespace
			helmServer *helmtestserver.HelmServer
			err        error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "helm-repository-" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			helmServer, err = helmtestserver.NewTempHelmServer()
			Expect(err).To(Succeed())
		})

		AfterEach(func() {
			helmServer.Stop()
			os.RemoveAll(helmServer.Root())

			Eventually(func() error {
				return k8sClient.Delete(context.Background(), namespace)
			}, timeout, interval).Should(Succeed(), "failed to delete test namespace")
		})

		It("Creates artifacts for", func() {
			helmServer.Start()

			Expect(helmServer.PackageChart(path.Join("testdata/charts/helmchart"))).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      helmServer.URL(),
					Interval: metav1.Duration{Duration: indexInterval},
					Timeout:  &metav1.Duration{Duration: repositoryTimeout},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			By("Expecting artifact")
			got := &sourcev1.HelmRepository{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil && ginkgoTestStorage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Updating the chart index")
			// Regenerating the index is sufficient to make the revision change
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			By("Expecting revision change and GC")
			Eventually(func() bool {
				now := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, now)
				// Test revision change and garbage collection
				return now.Status.Artifact.Revision != got.Status.Artifact.Revision &&
					!ginkgoTestStorage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			updated := &sourcev1.HelmRepository{}
			Expect(k8sClient.Get(context.Background(), key, updated)).Should(Succeed())
			updated.Spec.URL = "invalid#url?"
			Expect(k8sClient.Update(context.Background(), updated)).Should(Succeed())
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, updated)
				for _, c := range updated.Status.Conditions {
					if c.Reason == sourcev1.IndexationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(updated.Status.Artifact).ToNot(BeNil())

			By("Expecting to delete successfully")
			got = &sourcev1.HelmRepository{}
			Eventually(func() error {
				_ = k8sClient.Get(context.Background(), key, got)
				return k8sClient.Delete(context.Background(), got)
			}, timeout, interval).Should(Succeed())

			By("Expecting delete to finish")
			Eventually(func() error {
				r := &sourcev1.HelmRepository{}
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

		It("Handles timeout", func() {
			helmServer.Start()

			Expect(helmServer.PackageChart(path.Join("testdata/charts/helmchart"))).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      helmServer.URL(),
					Interval: metav1.Duration{Duration: indexInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), created)

			By("Expecting index download to succeed")
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, condition := range got.Status.Conditions {
					if condition.Reason == sourcev1.IndexationSucceededReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Expecting index download to timeout")
			updated := &sourcev1.HelmRepository{}
			Expect(k8sClient.Get(context.Background(), key, updated)).Should(Succeed())
			updated.Spec.Timeout = &metav1.Duration{Duration: time.Microsecond}
			Expect(k8sClient.Update(context.Background(), updated)).Should(Succeed())
			Eventually(func() string {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, condition := range got.Status.Conditions {
					if condition.Reason == sourcev1.IndexationFailedReason {
						return condition.Message
					}
				}
				return ""
			}, timeout, interval).Should(MatchRegexp("(?i)timeout"))
		})

		It("Authenticates when basic auth credentials are provided", func() {
			var username, password = "john", "doe"
			helmServer.WithMiddleware(func(handler http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					u, p, ok := r.BasicAuth()
					if !ok || username != u || password != p {
						w.WriteHeader(401)
						return
					}
					handler.ServeHTTP(w, r)
				})
			})
			helmServer.Start()

			Expect(helmServer.PackageChart(path.Join("testdata/charts/helmchart"))).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			secretKey := types.NamespacedName{
				Name:      "helmrepository-auth-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretKey.Name,
					Namespace: secretKey.Namespace,
				},
			}
			Expect(k8sClient.Create(context.Background(), secret)).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL: helmServer.URL(),
					SecretRef: &meta.LocalObjectReference{
						Name: secretKey.Name,
					},
					Interval: metav1.Duration{Duration: indexInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), created)

			By("Expecting 401")
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.IndexationFailedReason &&
						strings.Contains(c.Message, "401 Unauthorized") {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Expecting missing field error")
			secret.Data = map[string][]byte{
				"username": []byte(username),
			}
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Expecting artifact")
			secret.Data["password"] = []byte(password)
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil &&
					ginkgoTestStorage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Expecting missing secret error")
			Expect(k8sClient.Delete(context.Background(), secret)).Should(Succeed())
			got := &sourcev1.HelmRepository{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(got.Status.Artifact).ShouldNot(BeNil())
		})

		It("Authenticates when TLS credentials are provided", func() {
			err = helmServer.StartTLS(examplePublicKey, examplePrivateKey, exampleCA, "example.com")
			Expect(err).NotTo(HaveOccurred())

			Expect(helmServer.PackageChart(path.Join("testdata/charts/helmchart"))).Should(Succeed())
			Expect(helmServer.GenerateIndex()).Should(Succeed())

			secretKey := types.NamespacedName{
				Name:      "helmrepository-auth-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretKey.Name,
					Namespace: secretKey.Namespace,
				},
			}
			Expect(k8sClient.Create(context.Background(), secret)).Should(Succeed())

			key := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			created := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL: helmServer.URL(),
					SecretRef: &meta.LocalObjectReference{
						Name: secretKey.Name,
					},
					Interval: metav1.Duration{Duration: indexInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), created)

			By("Expecting unknown authority error")
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.IndexationFailedReason &&
						strings.Contains(c.Message, "certificate signed by unknown authority") {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Expecting missing field error")
			secret.Data = map[string][]byte{
				"certFile": examplePublicKey,
			}
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Expecting artifact")
			secret.Data["keyFile"] = examplePrivateKey
			secret.Data["caFile"] = exampleCA
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())
			Eventually(func() bool {
				got := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil &&
					ginkgoTestStorage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Expecting missing secret error")
			Expect(k8sClient.Delete(context.Background(), secret)).Should(Succeed())
			got := &sourcev1.HelmRepository{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(got.Status.Artifact).ShouldNot(BeNil())
		})
	})
})
