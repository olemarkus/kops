/*
Copyright 2019 The Kubernetes Authors.

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

package main

import (
	"fmt"
	"os"

	helmkube "helm.sh/helm/v3/pkg/kube"
	"k8s.io/klog/v2"
	"k8s.io/kops/channels/pkg/cmd"
)

func main() {
	klog.InitFlags(nil)

	// This will make kops the owner of the server-side-apply managed fields.
	// We set kops here instead of channels since should we change the addon manager from
	// channels to something else, we can still own the managed fields.
	helmkube.ManagedFieldsManager = "kops"

	f := &cmd.DefaultFactory{}
	if err := cmd.Execute(f, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		os.Exit(1)
	}
}
