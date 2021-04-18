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
	"context"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"k8s.io/kops/cmd/kops/util"
	"k8s.io/kops/pkg/pki"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/utils"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	createKeypairCaLong = templates.LongDesc(i18n.T(`
	Add a cluster CA certificate and private key.
    `))

	createKeypairCaExample = templates.Examples(i18n.T(`
	Add a cluster CA certificate and private key.
	kops create keypair ca \
		--cert ~/ca.pem --key ~/ca-key.pem \
		--name k8s-cluster.example.com --state s3://my-state-store
	`))

	createKeypairCaShort = i18n.T(`Add a cluster CA cert and key`)
)

type CreateKeypairCaOptions struct {
	ClusterName    string
	PrivateKeyPath string
	CertPath       string
}

// NewCmdCreateKeypairCa returns create ca certificate command
func NewCmdCreateKeypairCa(f *util.Factory, out io.Writer) *cobra.Command {
	options := &CreateKeypairCaOptions{}

	cmd := &cobra.Command{
		Use:     "ca",
		Short:   createKeypairCaShort,
		Long:    createKeypairCaLong,
		Example: createKeypairCaExample,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.TODO()

			err := rootCommand.ProcessArgs(args)
			if err != nil {
				exitWithError(err)
			}

			options.ClusterName = rootCommand.ClusterName()

			err = RunCreateKeypairCa(ctx, f, out, options)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	cmd.Flags().StringVar(&options.CertPath, "cert", options.CertPath, "Path to CA certificate")
	cmd.Flags().StringVar(&options.PrivateKeyPath, "key", options.PrivateKeyPath, "Path to CA private key")

	return cmd
}

// RunCreateKeypairCa adds a custom ca certificate and private key
func RunCreateKeypairCa(ctx context.Context, f *util.Factory, out io.Writer, options *CreateKeypairCaOptions) error {
	if options.CertPath == "" {
		return fmt.Errorf("error cert provided")
	}

	if options.PrivateKeyPath == "" {
		return fmt.Errorf("error no private key provided")
	}

	cluster, err := GetCluster(ctx, f, options.ClusterName)
	if err != nil {
		return fmt.Errorf("error getting cluster: %q: %v", options.ClusterName, err)
	}

	clientSet, err := f.Clientset()
	if err != nil {
		return fmt.Errorf("error getting clientset: %v", err)
	}

	keyStore, err := clientSet.KeyStore(cluster)
	if err != nil {
		return fmt.Errorf("error getting keystore: %v", err)
	}

	options.CertPath = utils.ExpandPath(options.CertPath)
	options.PrivateKeyPath = utils.ExpandPath(options.PrivateKeyPath)

	certBytes, err := ioutil.ReadFile(options.CertPath)
	if err != nil {
		return fmt.Errorf("error reading user provided cert %q: %v", options.CertPath, err)
	}
	privateKeyBytes, err := ioutil.ReadFile(options.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("error reading user provided private key %q: %v", options.PrivateKeyPath, err)
	}

	privateKey, err := pki.ParsePEMPrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("error loading private key %q: %v", privateKeyBytes, err)
	}
	cert, err := pki.ParsePEMCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("error loading certificate %q: %v", options.CertPath, err)
	}

	keyset := &fi.Keyset{
		Items: map[string]*fi.KeysetItem{},
	}
	err = keyset.AddItem(cert, privateKey)
	if err != nil {
		return err
	}

	err = keyStore.StoreKeyset(fi.CertificateIDCA, keyset)
	if err != nil {
		return fmt.Errorf("error storing user provided keys %q %q: %v", options.CertPath, options.PrivateKeyPath, err)
	}

	klog.Infof("using user provided cert: %v\n", options.CertPath)
	klog.Infof("using user provided private key: %v\n", options.PrivateKeyPath)

	return nil
}
