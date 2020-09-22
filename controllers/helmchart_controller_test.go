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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

var _ = Describe("HelmChartReconciler", func() {

	const (
		timeout       = time.Second * 30
		interval      = time.Second * 1
		indexInterval = time.Second * 2
		pullInterval  = time.Second * 3
	)

	Context("HelmChart from HelmRepository", func() {
		var (
			namespace  *corev1.Namespace
			helmServer *helmtestserver.HelmServer
			err        error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "helm-chart-test-" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			helmServer, err = helmtestserver.NewTempHelmServer()
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
					Chart:   "helmchart",
					Version: "",
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repositoryKey.Name,
					},
					Interval: metav1.Duration{Duration: pullInterval},
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

			By("Expecting missing HelmRepository error")
			updated := &sourcev1.HelmChart{}
			Expect(k8sClient.Get(context.Background(), key, updated)).Should(Succeed())
			updated.Spec.SourceRef.Name = "invalid"
			Expect(k8sClient.Update(context.Background(), updated)).Should(Succeed())
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, updated)
				for _, c := range updated.Status.Conditions {
					if c.Reason == sourcev1.ChartPullFailedReason &&
						strings.Contains(c.Message, "failed to retrieve source") {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(updated.Status.Artifact).ToNot(BeNil())

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
			}, timeout, interval).ShouldNot(Succeed())

			exists := func(path string) bool {
				// wait for tmp sync on macOS
				time.Sleep(time.Second)
				_, err := os.Stat(path)
				return err == nil
			}

			By("Expecting GC on delete")
			Eventually(exists(got.Status.Artifact.Path), timeout, interval).ShouldNot(BeTrue())
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
			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repositoryKey.Name,
					Namespace: repositoryKey.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL:      helmServer.URL(),
					Interval: metav1.Duration{Duration: 1 * time.Hour},
				},
			}
			Expect(k8sClient.Create(context.Background(), repository)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), repository)

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
					Chart:   "helmchart",
					Version: "*",
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repositoryKey.Name,
					},
					Interval: metav1.Duration{Duration: 1 * time.Hour},
				},
			}
			Expect(k8sClient.Create(context.Background(), chart)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), chart)

			Eventually(func() string {
				_ = k8sClient.Get(context.Background(), key, chart)
				if chart.Status.Artifact != nil {
					return chart.Status.Artifact.Revision
				}
				return ""
			}, timeout, interval).Should(Equal("1.0.0"))

			chart.Spec.Version = "<0.2.0"
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
			Expect(chart.GetArtifact()).NotTo(BeNil())
			Expect(chart.Status.Artifact.Revision).Should(Equal("0.1.1"))
		})

		It("Authenticates when credentials are provided", func() {
			helmServer.Stop()
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

			Expect(helmServer.PackageChartWithVersion(path.Join("testdata/helmchart"), "0.1.0")).Should(Succeed())
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
				Data: map[string][]byte{
					"username": []byte(username),
					"password": []byte(password),
				},
			}
			Expect(k8sClient.Create(context.Background(), secret)).Should(Succeed())

			By("Creating repository and waiting for artifact")
			repositoryKey := types.NamespacedName{
				Name:      "helmrepository-sample-" + randStringRunes(5),
				Namespace: namespace.Name,
			}
			repository := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repositoryKey.Name,
					Namespace: repositoryKey.Namespace,
				},
				Spec: sourcev1.HelmRepositorySpec{
					URL: helmServer.URL(),
					SecretRef: &corev1.LocalObjectReference{
						Name: secretKey.Name,
					},
					Interval: metav1.Duration{Duration: pullInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), repository)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), repository)

			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), repositoryKey, repository)
				return repository.Status.Artifact != nil
			}, timeout, interval).Should(BeTrue())

			By("Deleting secret before applying HelmChart")
			Expect(k8sClient.Delete(context.Background(), secret)).Should(Succeed())

			By("Applying HelmChart")
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
					Chart:   "helmchart",
					Version: "*",
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.HelmRepositoryKind,
						Name: repositoryKey.Name,
					},
					Interval: metav1.Duration{Duration: pullInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), chart)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), chart)

			By("Expecting missing secret error")
			got := &sourcev1.HelmChart{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason &&
						strings.Contains(c.Message, "auth secret error") {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Applying secret with missing keys")
			secret.ResourceVersion = ""
			secret.Data["username"] = []byte{}
			secret.Data["password"] = []byte{}
			Expect(k8sClient.Create(context.Background(), secret)).Should(Succeed())

			By("Expecting 401")
			Eventually(func() bool {
				got := &sourcev1.HelmChart{}
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.ChartPullFailedReason &&
						strings.Contains(c.Message, "401 Unauthorized") {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Adding username key")
			secret.Data["username"] = []byte(username)
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())

			By("Expecting missing field error")
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == sourcev1.AuthenticationFailedReason {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Adding password key")
			secret.Data["password"] = []byte(password)
			Expect(k8sClient.Update(context.Background(), secret)).Should(Succeed())

			By("Expecting artifact")
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Type == sourcev1.ReadyCondition && c.Status == corev1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
			Expect(got.Status.Artifact).ToNot(BeNil())
		})
	})

	Context("HelmChart from GitRepository", func() {
		var (
			namespace *corev1.Namespace
			gitServer *gittestserver.GitServer
			err       error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-git-repository-" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			gitServer, err = gittestserver.NewTempGitServer()
			Expect(err).NotTo(HaveOccurred())
			gitServer.AutoCreate()
			Expect(gitServer.StartHTTP()).To(Succeed())
		})

		AfterEach(func() {
			gitServer.StopHTTP()
			os.RemoveAll(gitServer.Root())

			err = k8sClient.Delete(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
		})

		It("Creates artifacts for", func() {
			fs := memfs.New()
			gitrepo, err := git.Init(memory.NewStorage(), fs)
			Expect(err).NotTo(HaveOccurred())

			wt, err := gitrepo.Worktree()
			Expect(err).NotTo(HaveOccurred())

			u, err := url.Parse(gitServer.HTTPAddress())
			Expect(err).NotTo(HaveOccurred())
			u.Path = path.Join(u.Path, fmt.Sprintf("repository-%s.git", randStringRunes(5)))

			_, err = gitrepo.CreateRemote(&config.RemoteConfig{
				Name: "origin",
				URLs: []string{u.String()},
			})
			Expect(err).NotTo(HaveOccurred())

			chartDir := "testdata/helmchart"
			Expect(filepath.Walk(chartDir, func(p string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				switch {
				case fi.Mode().IsDir():
					return fs.MkdirAll(p, os.ModeDir)
				case !fi.Mode().IsRegular():
					return nil
				}

				b, err := ioutil.ReadFile(p)
				if err != nil {
					return err
				}

				ff, err := fs.Create(p)
				if err != nil {
					return err
				}
				if _, err := ff.Write(b); err != nil {
					return err
				}
				_ = ff.Close()
				_, err = wt.Add(p)

				return err
			})).To(Succeed())

			_, err = wt.Commit("Helm chart", &git.CommitOptions{Author: &object.Signature{
				Name:  "John Doe",
				Email: "john@example.com",
				When:  time.Now(),
			}})
			Expect(err).NotTo(HaveOccurred())

			err = gitrepo.Push(&git.PushOptions{})
			Expect(err).NotTo(HaveOccurred())

			repositoryKey := types.NamespacedName{
				Name:      fmt.Sprintf("git-repository-sample-%s", randStringRunes(5)),
				Namespace: namespace.Name,
			}
			repository := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repositoryKey.Name,
					Namespace: repositoryKey.Namespace,
				},
				Spec: sourcev1.GitRepositorySpec{
					URL:      u.String(),
					Interval: metav1.Duration{Duration: indexInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), repository)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), repository)

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
					Chart:   "testdata/helmchart",
					Version: "*",
					SourceRef: sourcev1.LocalHelmChartSourceReference{
						Kind: sourcev1.GitRepositoryKind,
						Name: repositoryKey.Name,
					},
					Interval: metav1.Duration{Duration: pullInterval},
				},
			}
			Expect(k8sClient.Create(context.Background(), chart)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), chart)

			By("Expecting artifact")
			got := &sourcev1.HelmChart{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil &&
					storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())

			By("Committing a new version in the chart metadata")
			f, err := fs.OpenFile(fs.Join(chartDir, chartutil.ChartfileName), os.O_RDWR, os.FileMode(0600))
			Expect(err).NotTo(HaveOccurred())

			b := make([]byte, 1024)
			n, err := f.Read(b)
			Expect(err).NotTo(HaveOccurred())
			b = b[0:n]

			y := new(helmchart.Metadata)
			err = yaml.Unmarshal(b, y)
			Expect(err).NotTo(HaveOccurred())

			y.Version = "0.2.0"
			b, err = yaml.Marshal(y)
			Expect(err).NotTo(HaveOccurred())

			_, err = f.Write(b)
			Expect(err).NotTo(HaveOccurred())

			err = f.Close()
			Expect(err).NotTo(HaveOccurred())

			_, err = wt.Commit("Chart version bump", &git.CommitOptions{
				Author: &object.Signature{
					Name:  "John Doe",
					Email: "john@example.com",
					When:  time.Now(),
				},
				All: true,
			})
			Expect(err).NotTo(HaveOccurred())

			err = gitrepo.Push(&git.PushOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Expecting new artifact revision and GC")
			Eventually(func() bool {
				now := &sourcev1.HelmChart{}
				_ = k8sClient.Get(context.Background(), key, now)
				// Test revision change and garbage collection
				return now.Status.Artifact.Revision != got.Status.Artifact.Revision &&
					!storage.ArtifactExist(*got.Status.Artifact)
			}, timeout, interval).Should(BeTrue())
		})
	})
})
