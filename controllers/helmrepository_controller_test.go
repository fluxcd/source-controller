package controllers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo/repotest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

var _ = Describe("HelmRepositoryReconciler", func() {

	const (
		timeout  = time.Second * 30
		interval = time.Second * 1
	)

	var (
		namespace   *corev1.Namespace
		storage     *Storage
		helmRepoSrv *repotest.Server
		err         error
	)

	BeforeEach(func() {
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "helm-repository-" + randStringRunes(5)},
		}
		err = k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

		tmpStoragePath, err := ioutil.TempDir("", "helmrepository")
		Expect(err).NotTo(HaveOccurred(), "failed to create tmp storage dir")

		storage, err = NewStorage(tmpStoragePath, "localhost", timeout)
		Expect(err).NotTo(HaveOccurred(), "failed to create tmp storage")

		helmRepoSrv, err = makeHelmRepoSrv()
		Expect(err).NotTo(HaveOccurred(), "failed to setup tmp helm repository server")
		helmRepoSrv.Start()

		err = (&HelmRepositoryReconciler{
			Client:  k8sClient,
			Log:     ctrl.Log.WithName("controllers").WithName("HelmRepository"),
			Scheme:  scheme.Scheme,
			Storage: storage,
			Getters: getter.Providers{getter.Provider{
				Schemes: []string{"http", "https"},
				New:     getter.NewHTTPGetter,
			}},
		}).SetupWithManager(k8sManager)
		Expect(err).ToNot(HaveOccurred(), "failed to setup reconciler")

		go func() {
			err = k8sManager.Start(ctrl.SetupSignalHandler())
			Expect(err).ToNot(HaveOccurred())
		}()
	})

	AfterEach(func() {
		if storage != nil {
			os.RemoveAll(storage.BasePath)
		}
		if helmRepoSrv != nil {
			helmRepoSrv.Stop()
			os.RemoveAll(filepath.Dir(helmRepoSrv.Root()))
		}

		err := k8sClient.Delete(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
	})

	Context("HelmRepository", func() {
		It("Should create successfully", func() {
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
					URL:      helmRepoSrv.URL(),
					Interval: metav1.Duration{Duration: interval},
				},
			}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			got := &sourcev1.HelmRepository{}
			By("Expecting artifact")
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, got)
				return got.Status.Artifact != nil
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				return storage.ArtifactExist(*got.Status.Artifact)
			}).Should(BeTrue())

			By("Updating the chart index")
			// Regenerating the index is sufficient to make the revision change
			Expect(helmRepoSrv.CreateIndex()).Should(Succeed())
			Eventually(func() bool {
				r := &sourcev1.HelmRepository{}
				_ = k8sClient.Get(context.Background(), key, r)
				if r.Status.Artifact == nil {
					return false
				}
				return r.Status.Artifact.Revision != got.Status.Artifact.Revision
			}, timeout, interval).Should(BeTrue())

			updated := &sourcev1.HelmRepository{}
			Expect(k8sClient.Get(context.Background(), key, updated)).Should(Succeed())

			updated.Spec.Interval = metav1.Duration{Duration: 60 * time.Second}
			Expect(k8sClient.Update(context.Background(), updated)).Should(Succeed())

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
			}).ShouldNot(Succeed())
			Eventually(func() bool {
				return storage.ArtifactExist(*got.Status.Artifact)
			}).ShouldNot(BeTrue())
		})
	})
})

func makeHelmRepoSrv() (*repotest.Server, error) {
	tmpDir, err := ioutil.TempDir("", "helm-repo-srv")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp helm repository dir: %w", err)
	}

	pkg := action.NewPackage()
	pkg.Destination = tmpDir
	_, err = pkg.Run("testdata/helmchart", nil)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to package helm chart: %w", err)
	}

	srv := repotest.NewServer(path.Join(tmpDir, "*.tgz"))
	if err = srv.CreateIndex(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to create index for tmp helm repository: %w", err)
	}
	return srv, nil
}
