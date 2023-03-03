package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

func main() {
	srvhost := "localhost:433"
	caCertFile := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/PassBook.crt"
	clientCertFile := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/client.crt"
	clientKeyFile := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/client.key"

	var cert tls.Certificate
	var err error
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			log.Fatalf("Error creating x509 keypair from client cert file %s and client key file %s", clientCertFile, clientKeyFile)
		}
	}

	log.Printf("CAFile: %s", caCertFile)
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", caCertFile, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	client := http.Client{Transport: t, Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s", srvhost), bytes.NewBuffer([]byte("World")))
	if err != nil {
		log.Fatalf("unable to create http request due to error %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		switch e := err.(type) {
		case *url.Error:
			log.Fatalf("url.Error received on http request: %s", e)
		default:
			log.Fatalf("Unexpected error received: %s", err)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalf("unexpected error reading response body: %s", err)
	}

	fmt.Printf("\nResponse from server: \n\tHTTP status: %s\n\tBody: %s\n", resp.Status, body)
}
