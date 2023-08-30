package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
func handleHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.URL)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	var uninstall bool
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall the given certificate")
	//port := flag.Int("port", 8888, "the port on which the HTTP(S) proxy will run")
	flag.Parse()

	// verify existence of CACert for HTTPS MITM self-signing
	if err := ensureCACert(uninstall); err != nil {
		fmt.Printf("error handling certificates : %v\n", err)
		return
	}
	if uninstall {
		return
	}

	enableProxy()

	//disable proxy on ^C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		disableProxy()
		os.Exit(0)
	}()

	//disable proxy on end or panic
	defer func() {
		if r := recover(); r != nil {
			disableProxy()
		}
		fmt.Println("Cleaning up proxy on end")
		disableProxy()
	}()

	var pemPath string
	var keyPath string
	var proto string = "http"

	server := &http.Server{
		Addr: ":8888",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		//todo:  Why did I add this years ago?
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if proto == "http" {
		server.ListenAndServe()
	} else {
		server.ListenAndServeTLS(pemPath, keyPath)
	}
}

func enableProxy() {
	fmt.Println("Setting up proxy on localhost:8888")
	setWinInetProxy("localhost:8888")
	setWinEnvProxy("localhost:8888")
}

func disableProxy() {
	fmt.Println("Cleaning up proxy")
	setWinInetProxy("")
	setWinEnvProxy("")
}
