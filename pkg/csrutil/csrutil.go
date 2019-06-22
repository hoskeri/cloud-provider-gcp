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
	"reflect"
	"strings"

	authorization "k8s.io/api/authorization/v1beta1"
	capi "k8s.io/api/certificates/v1beta1"
)

type RecognizeFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
type ValidateFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) (bool, error)
type PreApproveFunc func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest, label string) error

var nodeClientKeyUsages = []capi.KeyUsage{
	capi.UsageKeyEncipherment,
	capi.UsageDigitalSignature,
	capi.UsageClientAuth,
}

var nodeServerKeyUsages = []capi.KeyUsage{
	capi.UsageKeyEncipherment,
	capi.UsageDigitalSignature,
	capi.UsageServerAuth,
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

	return hasExactUsages(csr, nodeClientKeyUsages)
}

func IsNodeServerCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !isNodeCert(x509cr) {
		return false
	}

	if !hasExactUsages(csr, nodeServerKeyUsages) {
		return false
	}

	return csr.Spec.Username == x509cr.Subject.CommonName
}
