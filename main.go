package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/etcd/client"
	ghandlers "github.com/gorilla/handlers"

)

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func main() {
	upstream := flag.String("upstream", "", "The upstream server.")
	upstreamCertFile := flag.String("upstream-cert-file", "", "identify HTTPS-enabled upstream servers using this SSL certificate file.")
	upstreamKeyFile := flag.String("upstream-key-file", "", "identify at HTTPS-enabled upstream servers using this SSL key file.")
	upstreamCAFile := flag.String("upstream-ca-file", "", "verify certificates of HTTPS-enabled upstream servers using this CA bundle.")

	listenClientURLsString := flag.String("listen-client-urls", "http://localhost:2379,http://localhost:4001", "list of URLs to listen on for client traffic.")
	certFile := flag.String("cert-file", "", "path to the client server TLS cert file.")
	keyFile := flag.String("key-file", "", "path to the client server TLS key file.")
	clientCertAuth := flag.Bool("client-cert-auth", false, "enable client cert authentication.")
	trustedCAFile := flag.String("trusted-ca-file", "", "verify certificates of HTTPS-enabled clients using this CA bundle")

	clientAdvertiseURLsString := flag.String("client-advertise-urls", "http://localhost:2379", "The client URL to advertise to the etcd clients.")
	k := flag.Bool("k", false, "Do not verify certificates.")

	flag.Parse()

	if *upstream == "" {
		log.Fatalf("Upstream server must be set.")
	}

	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatal(err)
	}

	if *clientAdvertiseURLsString == "" {
		log.Fatal("client-advertise-urls cannot be empty.")
	}
	clientAdvertiseURLs := strings.Split(*clientAdvertiseURLsString, ",")

	if *listenClientURLsString == "" {
		log.Fatal("listen-client-urls cannot be empty.")
	}
	listenClientURLs := []*url.URL{}
	for _, s := range strings.Split(*listenClientURLsString, ",") {
		u, err := url.Parse(s)
		if err != nil {
			log.Fatal(err)
		}
		if u.Path != "/" && u.Path != "" {
			log.Fatalf("Listen URL %q cannot have a path.", u.String())
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			log.Fatalf("Listen URL %q can only have scheme http or https.", u.String())
		}
		listenClientURLs = append(listenClientURLs, u)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{},
		InsecureSkipVerify: *k,
	}

	// possibly add client root-ca cert
	if *clientCertAuth {
		if *trustedCAFile == "" {
			log.Fatal("trusted-ca-file must be set.")
		}

		caCertPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(*upstreamCAFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else if *trustedCAFile != "" {
		log.Fatal("client-cert-auth must be enabled if a trusted CA file is set.")
	}

	// possibly add server root-ca cert
	if *upstreamCAFile != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(*upstreamCAFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	// load client certs
	if *upstreamCertFile != *upstreamKeyFile && (*upstreamCertFile == "" || *upstreamKeyFile == "") {
		log.Fatalf("Either none of upstream-cert-file and upstream-key-file must be set or none.")
	}
	if *upstreamCertFile != "" {
		cert, err := tls.LoadX509KeyPair(*upstreamCertFile, *upstreamKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	for _, u := range listenClientURLs {
		m := http.NewServeMux()

		m.HandleFunc("/v2/members", http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			d := struct {
				Members []client.Member
			}{
				Members: []client.Member{
					client.Member{
						ID: "0815081508150815",
						Name: "etcd2-proxy-proxy",
						PeerURLs: []string{},
						ClientURLs: clientAdvertiseURLs,
					},
				},
			}
			bs, _ := json.Marshal(d)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusOK)
			resp.Write(bs)
		}))

		m.Handle("/", &httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.URL.Scheme = upstreamURL.Scheme
				r.URL.Host = upstreamURL.Host
				r.URL.Path = singleJoiningSlash(upstreamURL.Path, r.URL.Path)
				r.Header.Set("Host", upstreamURL.Host)
			},
			Transport: transport,
		})

		go func (u *url.URL) {
			if u.Scheme == "http" {
				log.Fatal(http.ListenAndServe(u.Host,
					ghandlers.CombinedLoggingHandler(os.Stdout, m)))
			} else {
				if *certFile == "" {
					log.Fatal("cert-file must be set.")
				}
				if *keyFile == "" {
					log.Fatal("key-file must be set.")
				}
				go log.Fatal(http.ListenAndServeTLS(u.Host, *certFile, *keyFile,
					ghandlers.CombinedLoggingHandler(os.Stdout, m)))
			}
		}(u)

		log.Printf("Listening on %s\n", u.String())
	}

	c := make(chan struct{}, 0)
	<-c
}
