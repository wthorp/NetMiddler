package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var (
	printHeaders bool
	printBody    bool
	uninstall    bool
)

func main() {
	flag.BoolVar(&printHeaders, "print-headers", true, "Print HTTPS headers")
	flag.BoolVar(&printBody, "print-body", false, "Print HTTPS body")
	port := flag.Int("port", 8888, "the port on which the HTTP(S) proxy will run")
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall the given certificate")
	flag.Parse()

	// Ensure the CA certificate exists for HTTPS MITM self-signing
	if err := ensureCACert(uninstall); err != nil {
		fmt.Printf("Error handling certificates: %v\n", err)
		return
	}
	if uninstall {
		return
	}

	// Enable proxy at the given port
	enableProxy(*port)

	// Set up signal capturing for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Clean up the proxy on exit or panic
	defer func() {
		fmt.Println("Cleaning up proxy on exit")
		disableProxy()
	}()

	// Start proxy in a separate goroutine
	go func() {
		// Load the certificate (assumed that the CA is already installed)
		cert, err := tls.LoadX509KeyPair("netmiddler.pem", "netmiddler_pk.pem")
		if err != nil {
			log.Fatalf("Failed to load certificate: %v", err)
		}

		proxy := &Proxy{cert: cert}

		// Start HTTP proxy
		httpAddr := ":" + strconv.Itoa(*port)
		log.Printf("Starting HTTP proxy on %s\n", httpAddr)
		if err := http.ListenAndServe(httpAddr, proxy); err != nil {
			log.Fatalf("Failed to start HTTP proxy: %v", err)
		}
	}()

	// Wait for an interrupt (e.g., ^C) signal
	sig := <-sigChan
	fmt.Printf("\nReceived signal: %v, shutting down...\n", sig)

	// Exiting the main function will trigger the deferred `disableProxy`
}

// Proxy structure to hold configuration
type Proxy struct {
	cert tls.Certificate
}

// Implement ServeHTTP to make Proxy implement http.Handler
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle HTTPS connections
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		// Handle HTTP requests here if needed
		// You can implement similar MITM handling for HTTP requests if desired
		p.handleHTTP(w, r)
	}
}

// Handle HTTP traffic by forwarding it to the target host
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	transport := http.DefaultTransport
	outReq := new(http.Request)
	*outReq = *r
	outReq.RequestURI = ""
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Log the HTTP request
	log.Printf("HTTP %s %s %s", r.Method, r.URL, resp.Status)

	// Copy headers
	for key, value := range resp.Header {
		w.Header()[key] = value
	}
	w.WriteHeader(resp.StatusCode)

	// Log the body if printBody is true
	var bodyReader io.Reader = resp.Body
	if printBody {
		bodyReader = io.TeeReader(resp.Body, logWriter("HTTP Body: "))
	}

	io.Copy(w, bodyReader)
}

// Handle HTTPS connections with MITM attack
func (p *Proxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Cannot hijack connection", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Load the certificate (MITM certificate)
	cert, err := tls.LoadX509KeyPair("netmiddler.pem", "netmiddler_pk.pem")
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Establish a TLS connection with the client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   r.Host, // Use the requested host as the server name
	}

	log.Printf("Starting TLS handshake with client for host %s\n", r.Host)

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake with client failed: %v\n", err)
		return
	}
	log.Printf("TLS handshake with client succeeded for host %s\n", r.Host)

	defer tlsClientConn.Close()

	// Dial the target server
	log.Printf("Dialing target server %s\n", r.Host)
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Failed to connect to target server: %v\n", err)
		return
	}
	defer targetConn.Close()

	// Establish a TLS connection with the target server
	tlsTargetConn := tls.Client(targetConn, &tls.Config{
		InsecureSkipVerify: true,                          // Skip verifying the server's certificate for simplicity
		ServerName:         strings.Split(r.Host, ":")[0], // Extract the hostname
	})
	if err := tlsTargetConn.Handshake(); err != nil {
		log.Printf("TLS handshake with target server failed: %v\n", err)
		return
	}
	log.Printf("TLS handshake with target server succeeded for host %s\n", r.Host)

	defer tlsTargetConn.Close()

	// Log the HTTPS request
	log.Printf("HTTPS %s %s", r.Method, r.URL)

	// Tunnel data between client and target server
	go func() {
		io.Copy(tlsTargetConn, tlsClientConn)
	}()

	var bodyReader io.Reader = tlsTargetConn
	if printBody {
		bodyReader = io.TeeReader(tlsTargetConn, logWriter("HTTPS Body: "))
	}

	io.Copy(tlsClientConn, bodyReader)
}

func logWriter(prefix string) io.Writer {
	return &logWriterStruct{prefix: prefix}
}

type logWriterStruct struct {
	prefix string
}

func (w *logWriterStruct) Write(p []byte) (n int, err error) {
	log.Printf("%s%s", w.prefix, string(p))
	return len(p), nil
}
