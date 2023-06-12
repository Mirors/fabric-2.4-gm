/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package osnadmin

import (
	"context"
	"net"
	"net/http"

	tls "github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
)

func httpClient(caCertPool *x509.CertPool, tlsClientCert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}

				conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
					Certificates: []tls.Certificate{tlsClientCert},
					RootCAs:      caCertPool,
				})
				if err != nil {
					return nil, err
				}

				return conn, nil
			},
		},
	}
}

func httpDo(req *http.Request, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (*http.Response, error) {
	client := httpClient(caCertPool, tlsClientCert)
	return client.Do(req)
}

func httpGet(url string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (*http.Response, error) {
	client := httpClient(caCertPool, tlsClientCert)
	return client.Get(url)
}
