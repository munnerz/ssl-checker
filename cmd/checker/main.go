package main

import (
	"net/http"
	"time"
	"encoding/json"
	"sync"
	"fmt"
	"encoding/pem"
	"log"
	"crypto/x509"
	"io/ioutil"

	"github.com/namsral/flag"
	"github.com/bmatcuk/doublestar"
)

var (
	listenAddr = flag.String("listenAddr", "0.0.0.0:10000", "the address to listen on")
	watchGlob = flag.String("watch", "./**/cert.pem", "the directories to check for certificates")
	warningDuration = flag.Duration("warningDuration", time.Hour * 24 * 7, "how long until expiry before a certificate enters 'warning' state")
)

func main() {
	flag.Parse()

	http.HandleFunc("/", handle)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}

type CertStatus struct {
	// Subjects are the certificates domain names
	Subjects []string `json:"subjects"`

	// Expiry is the expiry time of this certificate
	Expiry time.Time `json:"expiry,omitempty"`

	// Status is a textual representation of the status of this certificate
	Status string `json:"status,omitempty"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	files, err := doublestar.Glob(*watchGlob);

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
	}

	// Create a buffered channel up to len(files)
	doneChan := make(chan *CertStatus, len(files))

	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)

		go func() {
			status, err := getCertStatus(f)

			if err != nil {
				log.Printf("Error getting certificate status for: %s", f)
			} else {
				doneChan <- status
			}

			wg.Done()
		}()
	}

	wg.Wait()
	close(doneChan)

	statuses := make([]*CertStatus, len(doneChan))

	i := 0
	for s := range doneChan {
		statuses[i] = s
		i++
	}

	err = json.NewEncoder(w).Encode(statuses)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
	}
}

func getCertStatus(path string) (*CertStatus, error) {
	d, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	p, remainder := pem.Decode(d)

	if len(remainder) == len(d) {
		return nil, fmt.Errorf("invalid PEM file: %s", path)
	}

	cert, err := x509.ParseCertificate(p.Bytes)

	if err != nil {
		return nil, err
	}

	status := "OKAY"
	if time.Now().After(cert.NotAfter.Add(-*warningDuration)) {
		status = "WARNING"
	}

	return &CertStatus{
		Subjects: cert.DNSNames,
		Expiry: cert.NotAfter,
		Status: status,
	}, nil
}