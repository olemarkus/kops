package controllers

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/kops/pkg/pki"
	"k8s.io/kops/upup/pkg/fi"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CertificateRequestReconciler struct {
	client   client.Client
	log      logr.Logger
	keystore pki.Keystore
}

func (r *CertificateRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	_ = r.log.WithValues("certificaterequestcontroller", req.NamespacedName)

	cr := &cmapi.CertificateRequest{}
	if err := r.client.Get(ctx, req.NamespacedName, cr); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	r.log.V(8).Info("reconciling ", cr.ObjectMeta.Name)

	if cr.Spec.IssuerRef.Group != "kops.k8s.io" {
		r.log.V(8).Info("resource is now owned by kops ", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	if len(cr.Status.Certificate) > 0 {
		r.log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}

	// Kops doesn't sign CAs
	if cr.Spec.IsCA {
		return ctrl.Result{}, nil
	}

	certRequest := cr.Spec.Request

	var csr = make([]byte, base64.StdEncoding.DecodedLen(len(certRequest)))
	var _, err = base64.StdEncoding.Decode(certRequest, csr)
	if err != nil {
		return ctrl.Result{}, err
	}

	block, _ := pem.Decode(csr)

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ctrl.Result{}, err
	}

	caCertificate, caPrivateKey, _, err := r.keystore.FindKeypair(fi.CertificateIDCA)

	signer := caCertificate.Certificate

	// create client certificate template
	template := x509.Certificate{
		BasicConstraintsValid: true,
		Signature:             crt.Signature,
		SignatureAlgorithm:    crt.SignatureAlgorithm,

		PublicKeyAlgorithm: crt.PublicKeyAlgorithm,
		PublicKey:          crt.PublicKey,

		SerialNumber: crt.SerialNumber,
		Issuer:       signer.Subject,
		Subject:      crt.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, &template, signer, crt.PublicKey, caPrivateKey.Key)
	if err != nil {
		return ctrl.Result{}, err
	}

	signedBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert})

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(signedBytes)))

	cr.Status.Certificate = b64

	return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Certificate issued")

}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...interface{}) error {
	completeMessage := fmt.Sprintf(message, args...)
	util.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	return r.client.Status().Update(ctx, cr)
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
