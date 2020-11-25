/*
Copyright 2020 The Kubernetes Authors.

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
	"fmt"

	"k8s.io/klog/v2"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretsReconciler observes Node objects, and labels them with the correct labels for the instancegroup
// This used to be done by the kubelet, but is moving to a central controller for greater security in 1.16
type SecretsReconciler struct {
	// client is the controller-runtime client
	client client.Client

	// log is a logr
	log logr.Logger

	// coreV1Client is a client-go client for patching nodes
	coreV1Client *corev1client.CoreV1Client

	// identifier is a provider that can securely map node ProviderIDs to labels
	secrets []string
}

// NewSecretsReconciler is the constructor for a SecretsReconciler
func NewSecretsReconciler(mgr manager.Manager, secrets []string) (*SecretsReconciler, error) {
	r := &SecretsReconciler{
		client:  mgr.GetClient(),
		log:     ctrl.Log.WithName("controllers").WithName("Secrets"),
		secrets: secrets,
	}

	coreClient, err := corev1client.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error building corev1 client: %v", err)
	}
	r.coreV1Client = coreClient

	return r, nil
}

func (r *SecretsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

func (r *SecretsReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	secrets, _ := r.coreV1Client.Secrets("kube-system").List(ctx, metav1.ListOptions{})
	for _, secret := range secrets.Items {
		klog.Infof("Found secret %v", secret.Name)
	}
	return ctrl.Result{}, nil
}
