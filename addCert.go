package main

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
