package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/publicsuffix"
)

//const baseURL = "https://127.0.0.1:4443"

const message = "hello"
const randomStringEntropyBytes = 32

var (
	baseURL = flag.String("baseURL", "https://127.0.0.1:4443", "A PEM eoncoded certificate file.")
)

type challengeResponseData struct {
	Nonce2 string `json:"nonce2"`
}

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil
}

func getNewCert(principals []string,
	client *http.Client,
	agentClient agent.ExtendedAgent,
	key *agent.Key) error {
	err := loginUsingAgent(client, agentClient, key)
	if err != nil {
		return err
	}

	res, err := client.Get(*baseURL + "/genToken")
	if err != nil {
		log.Println(err)
	}
	//log.Printf("res=%+v", res)
	robots, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", robots)

	return nil

}
func loginUsingAgent(client *http.Client,
	agentClient agent.ExtendedAgent,
	key *agent.Key) error {
	pubKey, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return err
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Println("SSH public key is not a certificate")
		fmt.Errorf("Not an SSH cert")
	}
	log.Printf("cert=%+v", sshCert)

	///// perform request
	// Nonce should be a a base64 encoded random number (256 bytes?)
	//nonce1 := "ITQeTfUgVMHL322SCBMcE4gsG4OLGCssgoMNCb+RAL4="
	nonce1, err := genRandomString()
	if err != nil {
		return err
	}
	values := url.Values{"sshCert": {key.String()}, "nonce1": {nonce1}}
	req, err := http.NewRequest("POST", *baseURL+"/getChallenge", strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("User-Agent", userAgentString)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//
	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("bad status response=%d", resp.StatusCode)
	}
	//log.Println(string(data))

	var newChallenge challengeResponseData
	err = json.Unmarshal(data, &newChallenge)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("challenge=%+v", newChallenge)

	hash := sha256.Sum256([]byte(nonce1 + newChallenge.Nonce2))
	//sign
	signature, err := agentClient.Sign(pubKey, hash[:])
	if err != nil {
		log.Println(err)
		return err
	}
	log.Printf("singature=%+v", signature)

	//
	values2 := url.Values{
		"nonce1":          {nonce1},
		"nonce2":          {newChallenge.Nonce2},
		"signatureFormat": {signature.Format},
		"signatureBlob":   {base64.URLEncoding.EncodeToString(signature.Blob)},
	}

	req2, err := http.NewRequest("POST", *baseURL+"/loginWithChallenge", strings.NewReader(values2.Encode()))
	if err != nil {
		return err
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req2.Header.Set("User-Agent", userAgentString)
	resp2, err := client.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	_, err = ioutil.ReadAll(resp2.Body)
	if err != nil {
		return err
	}
	if resp2.StatusCode >= 300 {
		return fmt.Errorf("bad status response=%d", resp.StatusCode)
	}
	/*
		// verify
		err = pubKey.Verify(hash[:], signature)
		if err != nil {
			log.Println(err)
			return err
		}
		signature2 := &ssh.Signature{
			Format: signature.Format,
			Blob:   signature.Blob,
		}
		err = pubKey.Verify(hash[:], signature2)
		if err != nil {
			log.Println(err)
			return err
		}
	*/
	log.Printf("Success")

	return nil
}

func main() {
	log.SetFlags(log.Lshortfile)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatalf("err=%s", err)
	}
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 25 * time.Second}
	/*
		res, err := client.Get(baseURL + "/hello")
		if err != nil {
			log.Println(err)
		}
		log.Printf("res=%+v", res)
		robots, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s", robots)
	*/
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)
	keyList, err := agentClient.List()

	for _, key := range keyList {
		//log.Printf("key=%+v, FORMAT=%s", key, key.Format)
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Println(err)
			continue
		}
		_, ok := pubKey.(*ssh.Certificate)
		if !ok {
			log.Println("SSH public key is not a certificate")
			continue
		}
		log.Printf("cert=%s", key.String())
		getNewCert([]string{"ubuntu"}, client, agentClient, key)

	}
}
