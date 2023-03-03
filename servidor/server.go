package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	//direccion del servidor
	host := "localhost"
	port := "433"
	//certificados
	serverCert := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/localhost.crt"
	caCert := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/PassBook.crt"
	srcKey := "/home/madanusculus/Desktop/SDS/Prаcticas/PassBook/cert/localhost.key"
	certOpt := 4 //Mutual TLS, MTLS, para la autenticación del cliente, máxima seguridad

	// Crear el servidor, con la configuración de TLS y timeouts
	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		TLSConfig:    getTLSConfig(host, caCert, tls.ClientAuthType(certOpt)),
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for host %s from IP address %s and X-FORWARDED-FOR %s",
			r.Method, r.Host, r.RemoteAddr, r.Header.Get("X-FORWARDED-FOR"))
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			body = []byte(fmt.Sprintf("error reading request body: %s", err))
		}
		resp := fmt.Sprintf("Hello jefe, %s from Advanced Server!", body)
		w.Write([]byte(resp))
		log.Printf("Advanced Server: Sent response %s", resp)
	})

	log.Printf("Starting HTTPS server on host %s and port %s", host, port)
	if err := server.ListenAndServeTLS(serverCert, srcKey); err != nil {
		log.Fatal(err)
	}
}

func getTLSConfig(host, caCertFile string, certOpt tls.ClientAuthType) *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool
	if certOpt > tls.RequestClientCert {
		caCert, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			log.Fatal("Error opening cert file", caCertFile, ", error ", err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	return &tls.Config{
		ServerName: host,
		// ClientAuth: tls.NoClientCert,				// Client certificate will not be requested and it is not required
		// ClientAuth: tls.RequestClientCert,			// Client certificate will be requested, but it is not required
		// ClientAuth: tls.RequireAnyClientCert,		// Client certificate is required, but any client certificate is acceptable
		// ClientAuth: tls.VerifyClientCertIfGiven,		// Client certificate will be requested and if present must be in the server's Certificate Pool
		// ClientAuth: tls.RequireAndVerifyClientCert,	// Client certificate will be required and must be present in the server's Certificate Pool
		ClientAuth: certOpt,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}
}
