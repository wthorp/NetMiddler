package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/smallstep/truststore"
)

func ensureCACert(uninstall bool) error {
	const caCertFile = "netmiddler.pem"

	if uninstall {
		if err := truststore.UninstallFile(caCertFile, truststore.WithJava(), truststore.WithFirefox()); err != nil {
			return err
		}
		if err := os.Remove(caCertFile); err != nil {
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
	const org = "NetMiddler"
	const commonName = "NetMiddler"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate certificate key %v", err)
		return err
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

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		log.Fatalf("Failed to create CA cert for apiserver %v", err)
		return err
	}
	signingCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		log.Fatalf("Failed to parse CA cert for apiserver %v", err)
		return err
	}

	caCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signingCert.Raw})
	return os.WriteFile(caCertFile, caCert, 600)
}
