package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/smallstep/truststore"
)

func ensureCACert(uninstall bool) error {
	const caCertFile = "netmiddler.pem"

	if uninstall {
		if err := truststore.UninstallFile(caCertFile, truststore.WithJava(), truststore.WithFirefox()); err != nil {
			//todo:  truststore seems to return errors here despite removing certs on Windows
			fmt.Printf("%v\n", err)
		}
		if err := os.Remove(caCertFile); err != nil {
			fmt.Println("Removing CA Cert file")
			return err
		}
		return nil
	}

	if _, err := os.Stat(caCertFile); err != nil {
		fmt.Println("Create CA Cert")
		if err = createCACert(caCertFile); err != nil {
			return err
		}
		if err := truststore.InstallFile(caCertFile, truststore.WithJava(), truststore.WithFirefox()); err != nil {
			return err
		}
	}

	return nil
}

func createCACert(caCertFile string) error {
	const org = "DO_NOT_TRUST_NetMiddlerRoot"
	const commonName = "DO_NOT_TRUST_NetMiddlerRoot"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate certificate key: %v", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(0),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{org}},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, privateKey.Public(), privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA cert for apiserver %v", err)
	}
	// Save the certificate to a PEM file
	certOut, err := os.Create("netmiddler.pem")
	if err != nil {
		return fmt.Errorf("failed to open proxy-cert.pem for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %v", err)
	}

	// Save the private key to a PEM file
	keyOut, err := os.Create("netmiddler_pk.pem")
	if err != nil {
		return fmt.Errorf("failed to open proxy-key.pem for writing: %v", err)
	}
	defer keyOut.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key to file: %v", err)
	}

	fmt.Println("Certificate and private key generated successfully.")
	return nil
}

// // register the CA with GoProxy
// func SetProxyCA(caCert, caKey []byte) error {
// 	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
// 	if err != nil {
// 		return err
// 	}
// 	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
// 		return err
// 	}
// 	goproxy.GoproxyCa = goproxyCa
// 	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
// 	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
// 	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
// 	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
// 	return nil
// }
