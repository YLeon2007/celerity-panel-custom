package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: cover port cert key")
	}
	s := &http.Server{
		Addr:              "127.0.0.1:" + os.Args[1],
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "isolated TLS test origin")
		}),
	}
	log.Fatal(s.ListenAndServeTLS(os.Args[2], os.Args[3]))
}
