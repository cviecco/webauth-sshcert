package main

import (
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"testing"

	"github.com/cviecco/webauth-sshcert/lib/server/sshcertauth"
)

func TestBase(t *testing.T) {
	// TODO have your own testing key so that we can actually test
	server := newServer([]string{"localhost"}, []string{trustedSigner})
	ts := httptest.NewTLSServer(server.HttpMux)
	defer ts.Close()

	client := ts.Client()
	res, err := client.Get(ts.URL + sshcertauth.DefaultCreateChallengePath)
	if err != nil {
		log.Fatal(err)
	}
	greeting, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting)

	res2, err := client.Get(ts.URL + sshcertauth.DefaultCreateChallengePath + "?nonce1=012345678901234567890123456789")
	if err != nil {
		log.Fatal(err)
	}

	greeting, err = io.ReadAll(res2.Body)
	res2.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting)
}
