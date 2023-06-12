/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nwo

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"time"

	tls "github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"

	. "github.com/onsi/gomega"
)

func OrdererOperationalClients(n *Network, o *Orderer) (authClient, unauthClient *http.Client) {
	return operationalClients(n, n.OrdererLocalTLSDir(o))
}

func PeerOperationalClients(n *Network, p *Peer) (authClient, unauthClient *http.Client) {
	return operationalClients(n, n.PeerLocalTLSDir(p))
}

func operationalClients(n *Network, tlsDir string) (authClient, unauthClient *http.Client) {
	fingerprint := "http::" + tlsDir
	if d := n.throttleDuration(fingerprint); d > 0 {
		time.Sleep(d)
	}

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(tlsDir, "server.crt"),
		filepath.Join(tlsDir, "server.key"),
	)
	Expect(err).NotTo(HaveOccurred())

	clientCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	Expect(err).NotTo(HaveOccurred())
	clientCertPool.AppendCertsFromPEM(caCert)

	authenticatedClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: -1,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}

				conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
					Certificates: []tls.Certificate{clientCert},
					RootCAs:      clientCertPool,
				})
				if err != nil {
					return nil, err
				}

				return conn, nil
			},
		},
	}
	unauthenticatedClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: -1,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}

				conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
					RootCAs: clientCertPool,
				})
				if err != nil {
					return nil, err
				}

				return conn, nil
			},
		},
	}

	return authenticatedClient, unauthenticatedClient
}
