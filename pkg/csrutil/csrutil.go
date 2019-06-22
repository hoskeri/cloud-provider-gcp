/*
Copyright 2018 The Kubernetes Authors.
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

// Package csrutil contains types for CSR approval workflows.
package csrutil

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	authorization "k8s.io/api/authorization/v1beta1"
	capi "k8s.io/api/certificates/v1beta1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/cloud-provider-gcp/pkg/csrmetrics"
	"k8s.io/klog"
	certutil "k8s.io/kubernetes/pkg/apis/certificates/v1beta1"
	"k8s.io/kubernetes/pkg/controller/certificates"
)

type RecognizeFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
type ValidateFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) (bool, error)
type PreApproveFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest, label string) error

var NodeClientKeyUsages = []capi.KeyUsage{
	capi.UsageKeyEncipherment,
	capi.UsageDigitalSignature,
	capi.UsageClientAuth,
}

var NodeServerKeyUsages = []capi.KeyUsage{
	capi.UsageKeyEncipherment,
	capi.UsageDigitalSignature,
	capi.UsageServerAuth,
}

type ValidatorInterface interface {
	Options() ValidatorOptions
	Recognize(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
	Validate(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) (bool, error)
	PreApproveHook(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) error
}

type ValidatorOptions struct {
	// Name for this validator, used in logging.
	Name string

	// Metrics Label
	Label string

	// Message to set when CSR is approved/denied
	ApproveMsg string
	DenyMsg    string

	// Subject Access Review Permissions
	Permission authorization.ResourceAttributes
}

type ValidatorContext struct {
	vs     []ValidatorInterface
	client clientset.Interface
}

// HandleCSR runs the certificate validation workflow
func (vc *ValidatorContext) HandleCSR(csr *capi.CertificateSigningRequest) error {
	recordMetric := csrmetrics.ApprovalStartRecorder("not_approved")
	if len(csr.Status.Certificate) != 0 {
		return nil
	}
	if approved, denied := certificates.GetCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}
	klog.Infof("approver got CSR %q", csr.Name)

	x509cr, err := certutil.ParseCSR(csr)
	if err != nil {
		recordMetric(csrmetrics.ApprovalStatusParseError)
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	var tried []string
	for _, r := range vc.vs {
		recordValidatorMetric := csrmetrics.ApprovalStartRecorder(r.Options().Label)
		if !r.Recognize(csr, x509cr) {
			continue
		}

		klog.Infof("validator %q: matched CSR %q", r.Options().Name, csr.Name)
		tried = append(tried, r.Options().Name)

		if r.Validate != nil {
			ok, err := r.Validate(csr, x509cr)
			if err != nil {
				return fmt.Errorf("validating CSR %q: %v", csr.Name, err)
			}
			if !ok {
				klog.Infof("validator %q: denied CSR %q", r.Options().Name, csr.Name)
				recordValidatorMetric(csrmetrics.ApprovalStatusDeny)
				return vc.UpdateCSR(csr, false, r.Options().DenyMsg)
			}
		}
		klog.Infof("CSR %q validation passed", csr.Name)

		approved, err := vc.SubjectAccessReview(csr, r.Options().Permission)
		if err != nil {
			recordValidatorMetric(csrmetrics.ApprovalStatusSARError)
			return err
		}

		if !approved {
			klog.Warningf("validator %q: SubjectAccessReview denied for CSR %q", r.Options().Name, csr.Name)
			continue
		}
		klog.Infof("validator %q: SubjectAccessReview approved for CSR %q", r.Options().Name, csr.Name)

		if r.PreApproveHook != nil {
			if err := r.PreApproveHook(csr, x509cr); err != nil {
				klog.Warningf("validator %q: preApproveHook failed for CSR %q: %v", r.Options().Name, csr.Name, err)
				recordValidatorMetric(csrmetrics.ApprovalStatusPreApproveHookError)
				return err
			}
			klog.Infof("validator %q: preApproveHook passed for CSR %q", r.Options().Label, csr.Name)
		}
		recordValidatorMetric(csrmetrics.ApprovalStatusApprove)
		return vc.UpdateCSR(csr, true, r.Options().ApproveMsg)
	}

	if len(tried) != 0 {
		recordMetric(csrmetrics.ApprovalStatusSARReject)
		return certificates.IgnorableError("recognized csr %q as %q but subject access review was not approved", csr.Name, tried)
	}

	klog.Infof("no validators matched CSR %q", csr.Name)
	recordMetric(csrmetrics.ApprovalStatusIgnore)
	return nil
}

func (vc *ValidatorContext) UpdateCSR(csr *capi.CertificateSigningRequest, approved bool, msg string) error {
	if approved {
		csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
			Type:    capi.CertificateApproved,
			Reason:  "AutoApproved",
			Message: msg,
		})
	} else {
		csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
			Type:    capi.CertificateDenied,
			Reason:  "AutoDenied",
			Message: msg,
		})
	}
	_, err := vc.client.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
	if err != nil {
		return fmt.Errorf("error updating approval status for csr: %v", err)
	}
	return nil
}

func (vc *ValidatorContext) SubjectAccessReview(csr *capi.CertificateSigningRequest, rattrs authorization.ResourceAttributes) (bool, error) {
	extra := make(map[string]authorization.ExtraValue)
	for k, v := range csr.Spec.Extra {
		extra[k] = authorization.ExtraValue(v)
	}

	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			User:               csr.Spec.Username,
			UID:                csr.Spec.UID,
			Groups:             csr.Spec.Groups,
			Extra:              extra,
			ResourceAttributes: &rattrs,
		},
	}
	sar, err := vc.client.AuthorizationV1beta1().SubjectAccessReviews().Create(sar)
	if err != nil {
		return false, err
	}
	return sar.Status.Allowed, nil
}

type Validator struct {
	Name           string
	AuthFlowLabel  string
	ApproveMsg     string
	DenyMsg        string
	Recognize      RecognizeFunc
	Validate       ValidateFunc
	PreApproveHook PreApproveFunc
	Permission     authorization.ResourceAttributes
}

func hasExactUsages(csr *capi.CertificateSigningRequest, usages []capi.KeyUsage) bool {
	if len(usages) != len(csr.Spec.Usages) {
		return false
	}

	usageMap := map[capi.KeyUsage]struct{}{}
	for _, u := range usages {
		usageMap[u] = struct{}{}
	}

	for _, u := range csr.Spec.Usages {
		if _, ok := usageMap[u]; !ok {
			return false
		}
	}

	return true
}

func isNodeCert(x509cr *x509.CertificateRequest) bool {
	if !reflect.DeepEqual([]string{"system:nodes"}, x509cr.Subject.Organization) {
		return false
	}

	if len(x509cr.EmailAddresses) > 0 {
		return false
	}

	return strings.HasPrefix(x509cr.Subject.CommonName, "system:node:")
}

func IsNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !isNodeCert(x509cr) {
		return false
	}

	if len(x509cr.DNSNames) > 0 || len(x509cr.IPAddresses) > 0 {
		return false
	}

	return hasExactUsages(csr, NodeClientKeyUsages)
}

func IsNodeServerCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !isNodeCert(x509cr) {
		return false
	}

	if !hasExactUsages(csr, NodeServerKeyUsages) {
		return false
	}

	return csr.Spec.Username == x509cr.Subject.CommonName
}
