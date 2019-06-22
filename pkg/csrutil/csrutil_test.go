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

package csrutil

import (
	"os"
	"testing"

	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/klog"
)

func init() {
	klog.SetOutput(os.Stderr)
}

func TestHasKubeletUsages(t *testing.T) {
	cases := []struct {
		usages   []capi.KeyUsage
		expected bool
	}{
		{
			usages:   nil,
			expected: false,
		},
		{
			usages:   []capi.KeyUsage{},
			expected: false,
		},
		{
			usages: []capi.KeyUsage{
				capi.UsageKeyEncipherment,
				capi.UsageDigitalSignature,
			},
			expected: false,
		},
		{
			usages: []capi.KeyUsage{
				capi.UsageKeyEncipherment,
				capi.UsageDigitalSignature,
				capi.UsageServerAuth,
			},
			expected: false,
		},
		{
			usages: []capi.KeyUsage{
				capi.UsageKeyEncipherment,
				capi.UsageDigitalSignature,
				capi.UsageClientAuth,
			},
			expected: true,
		},
	}
	for _, c := range cases {
		if hasExactUsages(&capi.CertificateSigningRequest{
			Spec: capi.CertificateSigningRequestSpec{
				Usages: c.usages,
			},
		}, nodeClientKeyUsages) != c.expected {
			t.Errorf("unexpected result of hasKubeletUsages(%v), expecting: %v", c.usages, c.expected)
		}
	}
}
