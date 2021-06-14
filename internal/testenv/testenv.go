/*
Copyright 2020 The Kubernetes Authors.
Copyright 2021 The Flux authors

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

package testenv

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
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
}

var (
	cacheSyncBackoff = wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.5,
		Steps:    8,
		Jitter:   0.4,
	}

	errAlreadyStarted = errors.New("environment has already been started")
	errAlreadyStopped = errors.New("environment has already been stopped")
)

// Environment encapsulates a Kubernetes local test environment.
type Environment struct {
	manager.Manager
	client.Client
	Config *rest.Config

	env           *envtest.Environment
	startOnce     sync.Once
	stopOnce      sync.Once
	cancelManager context.CancelFunc
}

// options holds the configuration options for the Environment.
type options struct {
	scheme            *runtime.Scheme
	crdDirectoryPaths []string
}

// withDefaults sets the default configuration for missing values.
func (o *options) withDefaults() {
	if o.scheme == nil {
		utilruntime.Must(scheme.AddToScheme(scheme.Scheme))
		o.scheme = scheme.Scheme
	}
}

// Option sets a configuration for the Environment.
type Option func(*options)

// WithScheme configures the runtime.Scheme for the Environment.
func WithScheme(scheme *runtime.Scheme) Option {
	return func(o *options) {
		o.scheme = scheme
	}
}

// WithCRDPath configures the paths the envtest.Environment should look
// at for Custom Resource Definitions.
func WithCRDPath(path ...string) Option {
	return func(o *options) {
		o.crdDirectoryPaths = append(o.crdDirectoryPaths, path...)
	}
}

// New creates a new environment spinning up a local api-server.
//
// NOTE: This function should be called only once for each package you're
// running tests within, usually the environment is initialized in a
// suite_test.go or <package>_test.go file within a `TestMain` function.
func New(o ...Option) *Environment {
	opts := options{}
	for _, apply := range o {
		apply(&opts)
	}
	opts.withDefaults()

	env = &envtest.Environment{
		ErrorIfCRDPathMissing: true,
		CRDDirectoryPaths:     opts.crdDirectoryPaths,
	}

	if _, err := env.Start(); err != nil {
		err = kerrors.NewAggregate([]error{err, env.Stop()})
		panic(err)
	}

	mgr, err := ctrl.NewManager(env.Config, manager.Options{
		Scheme:             opts.scheme,
		MetricsBindAddress: "0",
		CertDir:            env.WebhookInstallOptions.LocalServingCertDir,
		Port:               env.WebhookInstallOptions.LocalServingPort,
	})
	if err != nil {
		klog.Fatalf("Failed to start testenv manager: %v", err)
	}

	return &Environment{
		Manager: mgr,
		Client:  mgr.GetClient(),
		Config:  mgr.GetConfig(),
		env:     env,
	}
}

// Start starts the test environment.
func (e *Environment) Start(ctx context.Context) error {
	err := errAlreadyStarted
	e.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(ctx)
		e.cancelManager = cancel
		err = e.Manager.Start(ctx)
	})
	return err
}

// Stop stops the test environment.
func (e *Environment) Stop() error {
	err := errAlreadyStopped
	e.stopOnce.Do(func() {
		e.cancelManager()
		err = e.env.Stop()
	})
	return err
}

// Cleanup deletes all the given objects.
func (e *Environment) Cleanup(ctx context.Context, objs ...client.Object) error {
	errs := []error{}
	for _, o := range objs {
		err := e.Client.Delete(ctx, o)
		if apierrors.IsNotFound(err) {
			continue
		}
		errs = append(errs, err)
	}
	return kerrors.NewAggregate(errs)
}

// CleanupAndWait deletes all the given objects and waits for the cache to be updated accordingly.
//
// NOTE: Waiting for the cache to be updated helps in preventing test flakes due to the cache sync delays.
func (e *Environment) CleanupAndWait(ctx context.Context, objs ...client.Object) error {
	if err := e.Cleanup(ctx, objs...); err != nil {
		return err
	}

	// Makes sure the cache is updated with the deleted object
	errs := []error{}
	for _, o := range objs {
		// Ignoring namespaces because in testenv the namespace cleaner is not running.
		if o.GetObjectKind().GroupVersionKind().GroupKind() == corev1.SchemeGroupVersion.WithKind("Namespace").GroupKind() {
			continue
		}

		oCopy := o.DeepCopyObject().(client.Object)
		key := client.ObjectKeyFromObject(o)
		err := wait.ExponentialBackoff(
			cacheSyncBackoff,
			func() (done bool, err error) {
				if err := e.Get(ctx, key, oCopy); err != nil {
					if apierrors.IsNotFound(err) {
						return true, nil
					}
					return false, err
				}
				return false, nil
			})
		errs = append(errs, errors.Wrapf(err, "key %s, %s is not being deleted from the testenv client cache", o.GetObjectKind().GroupVersionKind().String(), key))
	}
	return kerrors.NewAggregate(errs)
}

// CreateAndWait creates the given object and waits for the cache to be updated accordingly.
//
// NOTE: Waiting for the cache to be updated helps in preventing test flakes due to the cache sync delays.
func (e *Environment) CreateAndWait(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := e.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}

	// Makes sure the cache is updated with the new object
	objCopy := obj.DeepCopyObject().(client.Object)
	key := client.ObjectKeyFromObject(obj)
	if err := wait.ExponentialBackoff(
		cacheSyncBackoff,
		func() (done bool, err error) {
			if err := e.Get(ctx, key, objCopy); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		}); err != nil {
		return errors.Wrapf(err, "object %s, %s is not being added to the testenv client cache", obj.GetObjectKind().GroupVersionKind().String(), key)
	}
	return nil
}

// CreateNamespace creates a new namespace with a generated name.
func (e *Environment) CreateNamespace(ctx context.Context, generateName string) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", generateName),
			Labels: map[string]string{
				"testenv/original-name": generateName,
			},
		},
	}
	if err := e.Client.Create(ctx, ns); err != nil {
		return nil, err
	}
	return ns, nil
}
