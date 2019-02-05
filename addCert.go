package main


/// todo: use https://github.com/FiloSottile/mkcert

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

//TODO:  determine if this is useful
func main() {
	caCert, err := ioutil.ReadFile("rootCA.crt")
	if err != nil {
		log.Fatal(err)
	}
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		fmt.Println("Failed to get SystemCertPool")
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile(localCertFile)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", localCertFile, err)
	}

	rootCAs.AppendCertsFromPEM(caCert)
}

func loadSystemRoots() (*CertPool, error) {
	// TODO: restore this functionality on Windows. We tried to do
	// it in Go 1.8 but had to revert it. See Issue 18609.
	// Returning (nil, nil) was the old behavior, prior to CL 30578.
	return nil, nil

	const CRYPT_E_NOT_FOUND = 0x80092004

	store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("ROOT"))
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)
] //CertCloseStore(hRootCertStore,0);
