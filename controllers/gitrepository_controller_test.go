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
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/testserver"
)

var _ = Describe("GitRepositoryReconciler", func() {

	const (
		timeout       = time.Second * 30
		interval      = time.Second * 1
		indexInterval = time.Second * 1
	)

	Context("GitRepository", func() {
		var (
			namespace *corev1.Namespace
			gitServer *testserver.GitServer
			err       error
		)

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "git-repository-test" + randStringRunes(5)},
			}
			err = k8sClient.Create(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

			gitServer, err = testserver.NewTempGitServer()
			Expect(err).NotTo(HaveOccurred())
			gitServer.AutoCreate()
		})

		AfterEach(func() {
			os.RemoveAll(gitServer.Root())

			err = k8sClient.Delete(context.Background(), namespace)
			Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
		})

		type refTestCase struct {
			reference  *sourcev1.GitRepositoryRef
			createRefs []string

			waitForReason string

			expectStatus   corev1.ConditionStatus
			expectMessage  string
			expectRevision string
		}

		DescribeTable("Git references tests", func(t refTestCase) {
			err = gitServer.StartHTTP()
			defer gitServer.StopHTTP()
			Expect(err).NotTo(HaveOccurred())

			u, err := url.Parse(gitServer.HTTPAddress())
			Expect(err).NotTo(HaveOccurred())
			u.Path = path.Join(u.Path, fmt.Sprintf("repository-%s.git", randStringRunes(5)))

			fs := memfs.New()
			gitrepo, err := git.Init(memory.NewStorage(), fs)
			Expect(err).NotTo(HaveOccurred())

			wt, err := gitrepo.Worktree()
			Expect(err).NotTo(HaveOccurred())

			ff, _ := fs.Create("fixture")
			_ = ff.Close()
			_, err = wt.Add(fs.Join("fixture"))
			Expect(err).NotTo(HaveOccurred())

			commit, err := wt.Commit("Sample", &git.CommitOptions{Author: &object.Signature{
				Name:  "John Doe",
				Email: "john@example.com",
				When:  time.Now(),
			}})
			Expect(err).NotTo(HaveOccurred())

			gitrepo.Worktree()

			for _, ref := range t.createRefs {
				hRef := plumbing.NewHashReference(plumbing.ReferenceName(ref), commit)
				err = gitrepo.Storer.SetReference(hRef)
				Expect(err).NotTo(HaveOccurred())
			}

			remote, err := gitrepo.CreateRemote(&config.RemoteConfig{
				Name: "origin",
				URLs: []string{u.String()},
			})
			Expect(err).NotTo(HaveOccurred())

			err = remote.Push(&git.PushOptions{
				RefSpecs: []config.RefSpec{"refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"},
			})
			Expect(err).NotTo(HaveOccurred())

			t.reference.Commit = strings.Replace(t.reference.Commit, "<commit>", commit.String(), 1)

			key := types.NamespacedName{
				Name:      fmt.Sprintf("git-ref-test-%s", randStringRunes(5)),
				Namespace: namespace.Name,
			}
			created := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: sourcev1.GitRepositorySpec{
					URL:       u.String(),
					Interval:  metav1.Duration{Duration: indexInterval},
					Reference: t.reference,
				},
			}
			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())
			defer k8sClient.Delete(context.Background(), created)

			got := &sourcev1.GitRepository{}
			var cond sourcev1.SourceCondition
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				for _, c := range got.Status.Conditions {
					if c.Reason == t.waitForReason {
						cond = c
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			Expect(cond.Status).To(Equal(t.expectStatus))
			Expect(cond.Message).To(ContainSubstring(t.expectMessage))
			Expect(got.Status.Artifact == nil).To(Equal(t.expectRevision == ""))
			if t.expectRevision != "" {
				Expect(got.Status.Artifact.Revision).To(Equal(t.expectRevision + "/" + commit.String()))
			}
		},
			Entry("branch", refTestCase{
				reference:      &sourcev1.GitRepositoryRef{Branch: "some-branch"},
				createRefs:     []string{"refs/heads/some-branch"},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "some-branch",
			}),
			Entry("branch non existing", refTestCase{
				reference:     &sourcev1.GitRepositoryRef{Branch: "invalid-branch"},
				waitForReason: sourcev1.GitOperationFailedReason,
				expectStatus:  corev1.ConditionFalse,
				expectMessage: "couldn't find remote ref",
			}),
			Entry("tag", refTestCase{
				reference:      &sourcev1.GitRepositoryRef{Tag: "some-tag"},
				createRefs:     []string{"refs/tags/some-tag"},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "some-tag",
			}),
			Entry("tag non existing", refTestCase{
				reference:     &sourcev1.GitRepositoryRef{Tag: "invalid-tag"},
				waitForReason: sourcev1.GitOperationFailedReason,
				expectStatus:  corev1.ConditionFalse,
				expectMessage: "couldn't find remote ref",
			}),
			Entry("semver", refTestCase{
				reference:      &sourcev1.GitRepositoryRef{SemVer: "1.0.0"},
				createRefs:     []string{"refs/tags/v1.0.0"},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "v1.0.0",
			}),
			Entry("semver range", refTestCase{
				reference:      &sourcev1.GitRepositoryRef{SemVer: ">=0.1.0 <1.0.0"},
				createRefs:     []string{"refs/tags/0.1.0", "refs/tags/0.1.1", "refs/tags/0.2.0", "refs/tags/1.0.0"},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "0.2.0",
			}),
			Entry("semver invalid", refTestCase{
				reference:     &sourcev1.GitRepositoryRef{SemVer: "v1.0.0"},
				waitForReason: sourcev1.GitOperationFailedReason,
				expectStatus:  corev1.ConditionFalse,
				expectMessage: "semver parse range error",
			}),
			Entry("semver no match", refTestCase{
				reference:     &sourcev1.GitRepositoryRef{SemVer: "1.0.0"},
				waitForReason: sourcev1.GitOperationFailedReason,
				expectStatus:  corev1.ConditionFalse,
				expectMessage: "no match found for semver: 1.0.0",
			}),
			Entry("commit", refTestCase{
				reference: &sourcev1.GitRepositoryRef{
					Commit: "<commit>",
				},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "master",
			}),
			Entry("commit in branch", refTestCase{
				reference: &sourcev1.GitRepositoryRef{
					Branch: "some-branch",
					Commit: "<commit>",
				},
				createRefs:     []string{"refs/heads/some-branch"},
				waitForReason:  sourcev1.GitOperationSucceedReason,
				expectStatus:   corev1.ConditionTrue,
				expectRevision: "some-branch",
			}),
			Entry("invalid commit", refTestCase{
				reference: &sourcev1.GitRepositoryRef{
					Branch: "master",
					Commit: "invalid",
				},
				waitForReason: sourcev1.GitOperationFailedReason,
				expectStatus:  corev1.ConditionFalse,
				expectMessage: "git commit 'invalid' not found: object not found",
			}),
		)
	})
})
