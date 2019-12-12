package sshAutn

import (
	"crypto/rand"
	"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/cviecco/webauth-sshcert/lib/server/sshCertAuth"
)

const randomStringEntropyBytes = 32

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil
}

func (s *SSHAuthenticator) loggerPrintf(level uint, format string, v ...interface{}) {
	if level <= s.LogLevel {
		log.Printf(format, v...)
	}
}

func (s *SSHAuthenticator) loginWithCertAndAgent(
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
	s.loggerPrintf(2, "cert=%+v", sshCert)

	///// perform request
	// Nonce should be a a base64 encoded random number (256 bytes?)
	nonce1, err := genRandomString()
	if err != nil {
		return err
	}
	values := url.Values{"sshCert": {key.String()}, "nonce1": {nonce1}}
	req, err := http.NewRequest("POST", s.rawBaseURL+s.getChallengePath, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("User-Agent", userAgentString)
	resp, err := s.client.Do(req)
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

	var newChallenge sshCertAuth.ChallengeResponseData
	err = json.Unmarshal(data, &newChallenge)
	if err != nil {
		log.Fatal(err)
	}

	s.loggerPrintf(1, "challenge=%+v", newChallenge)

	hash := sha256.Sum256([]byte(nonce1 + newChallenge.Challenge))
	//sign
	signature, err := agentClient.Sign(pubKey, hash[:])
	if err != nil {
		log.Println(err)
		return err
	}
	s.loggerPrintf(2, "singature=%+v", signature)

	//
	values2 := url.Values{
		"nonce1":          {nonce1},
		"challenge":       {newChallenge.Challenge},
		"hostname":        {s.baseURL.Hostname()},
		"signatureFormat": {signature.Format},
		"signatureBlob":   {base64.URLEncoding.EncodeToString(signature.Blob)},
	}

	req2, err := http.NewRequest("POST", s.rawBaseURL+s.loginWithChallengePath, strings.NewReader(values2.Encode()))
	if err != nil {
		return err
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req2.Header.Set("User-Agent", userAgentString)
	resp2, err := s.client.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		return err
	}
	if resp2.StatusCode >= 300 {
		return fmt.Errorf("bad status response=%d, data=%s", resp2.StatusCode, string(responseBytes))
	}
	s.loggerPrintf(1, "Login Success")

	return nil

}

func (s *SSHAuthenticator) loginWithAgentSocket() error {
	socket := os.Getenv("SSH_AUTH_SOCK")
	// TODO: check on windows
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("LoginWithAgentSocket: Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)
	keyList, err := agentClient.List()

	var lastErr error
	for _, key := range keyList {
		//log.Printf("key=%+v, FORMAT=%s", key, key.Format)
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Println(err)
			continue
		}
		_, ok := pubKey.(*ssh.Certificate)
		if !ok {
			s.loggerPrintf(1, "SSH public key is not a certificate")
			continue
		}
		s.loggerPrintf(2, "cert=%s", key.String())
		lastErr = s.loginWithCertAndAgent(agentClient, key)
		if lastErr != nil {
			log.Printf("Error using cert %s", key.String())
			continue
		}
		return nil

	}
	return fmt.Errorf("Could not login, last err=%s", lastErr)
}
