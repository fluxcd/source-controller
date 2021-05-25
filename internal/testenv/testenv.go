package testenv

import (
	"context"
	"fmt"

	"github.com/onsi/ginkgo"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	env *envtest.Environment
)

func init() {
	klog.InitFlags(nil)
	logger := klogr.New()
	log.SetLogger(logger)
	ctrl.SetLogger(logger)
	klog.SetOutput(ginkgo.GinkgoWriter)
}

func init() {
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme.Scheme))
	// Others can be added before calling NewTestEnvironment.
}

// TestEnvironment encapsulates a Kubernetes local test environment.
type TestEnvironment struct {
	manager.Manager
	client.Client
	Config *rest.Config

	cancel context.CancelFunc
}

// NewTestEnvironment creates a new environment spinning up a local api-server.
func NewTestEnvironment(crdDirPaths []string) *TestEnvironment {
	env = &envtest.Environment{
		ErrorIfCRDPathMissing: true,
		CRDDirectoryPaths:     crdDirPaths,
	}

	if _, err := env.Start(); err != nil {
		err = kerrors.NewAggregate([]error{err, env.Stop()})
		panic(err)
	}

	options := manager.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
		CertDir:            env.WebhookInstallOptions.LocalServingCertDir,
		Port:               env.WebhookInstallOptions.LocalServingPort,
	}

	mgr, err := ctrl.NewManager(env.Config, options)
	if err != nil {
		klog.Fatalf("Failed to start testenv manager: %v", err)
	}

	return &TestEnvironment{
		Manager: mgr,
		Client:  mgr.GetClient(),
		Config:  mgr.GetConfig(),
	}
}

func (t *TestEnvironment) StartManager(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	return t.Manager.Start(ctx)
}

func (t *TestEnvironment) Stop() error {
	t.cancel()
	return env.Stop()
}

func (t *TestEnvironment) Cleanup(ctx context.Context, objs ...client.Object) error {
	var errs []error
	for _, o := range objs {
		err := t.Client.Delete(ctx, o)
		if apierrors.IsNotFound(err) {
			// If the object is not found, it must've been garbage collected
			// already. For example, if we delete namespace first and then
			// objects within it.
			continue
		}
		errs = append(errs, err)
	}
	return kerrors.NewAggregate(errs)
}

func (t *TestEnvironment) CreateNamespace(ctx context.Context, generateName string) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", generateName),
			Labels: map[string]string{
				"testenv/original-name": generateName,
			},
		},
	}
	if err := t.Client.Create(ctx, ns); err != nil {
		return nil, err
	}
	return ns, nil
}
