/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package osnadmin

import (
	"fmt"
	tls "github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"net/http"
)

// Lists the channels an OSN is a member of.
func ListAllChannels(osnURL string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (*http.Response, error) {
	url := fmt.Sprintf("%s/participation/v1/channels", osnURL)

	return httpGet(url, caCertPool, tlsClientCert)
}

// Lists a single channel an OSN is a member of.
func ListSingleChannel(osnURL, channelID string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (*http.Response, error) {
	url := fmt.Sprintf("%s/participation/v1/channels/%s", osnURL, channelID)

	return httpGet(url, caCertPool, tlsClientCert)
}
