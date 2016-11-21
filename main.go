package main

import (
	"errors"
	"github.com/mvdan/xurls"
	"golang.org/x/net/idna"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	if nil == req.URL || "https" != req.URL.Scheme {
		if len(via) > 0 {
			return http.ErrUseLastResponse
		}
		return errors.New("non-https redirect attempted")
	}
	return nil
}

func main() {

	seen := make(map[string]bool)

	client := &http.Client{
		CheckRedirect: checkRedirect,
		Timeout:       time.Duration(10 * time.Second),
	}

	encoded, err := idna.ToASCII(os.Args[1])
	if nil != err {
		log.Fatal(err)
	}

	resp, err := client.Get("https://" + encoded + "/")
	if nil != err {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	chunk := make([]byte, 1024*1024)
	read, err := resp.Body.Read(chunk)
	chunk = chunk[:read]

	for _, bytes := range xurls.Strict.FindAll(chunk, -1) {
		full, err := url.Parse(string(bytes[:]))
		if nil != err || nil == full {
			continue
		}
		seen[full.Host] = true
	}

	if nil != resp.TLS && nil != resp.TLS.PeerCertificates {
		for _, cert := range resp.TLS.PeerCertificates {
			if nil != cert.DNSNames && len(cert.DNSNames) > 0 {
				for _, name := range cert.DNSNames {
					seen[name] = true
				}
			}
		}
	}

	for name, _ := range seen {
		if strings.ContainsRune(name, ':') || !strings.ContainsRune(name, '.') {
			continue
		}
		log.Print(name)
	}
}
