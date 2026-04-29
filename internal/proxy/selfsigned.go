// Self-signed cert generator. Used to put the detector behind TLS
// without operator-supplied certificates, which is required because
// kubectl refuses to send bearer tokens over plain HTTP.
//
// In production, you'd terminate TLS at an Ingress with a real cert.
// This in-process self-signed mode is the path of least friction for
// the SSH-tunnel / port-forward developer setup, paired with
// insecure-skip-tls-verify in the generated kubeconfig.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// SelfSignedCert returns a TLS certificate good for one year, valid
// for the cluster-internal DNS names a detector pod is reachable
// under. The host arg is the operator-provided name (DNS or IP) the
// users will actually hit; we add it as a SAN.
func SelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "podpulse"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			"localhost",
			"podpulse",
			"podpulse-detector",
			"podpulse-detector.podpulse-dev",
			"podpulse-detector.podpulse-dev.svc",
			"podpulse-detector.podpulse-dev.svc.cluster.local",
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host != "" && host != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
