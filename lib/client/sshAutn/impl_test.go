package sshAutn

import (
	"bytes"
	//"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/cviecco/webauth-sshcert/lib/server/sshCertAuth"
)

func generateNewTestCertSignerAndAgent(t *testing.T) (ssh.Signer, ssh.Certificate, agent.Agent, error) {

	signerPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(signerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	t.Logf("userPub is %T", userPub)
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(30)
	cert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		SignatureKey:    signer.PublicKey(),
		ValidPrincipals: []string{"someuser"},
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:  userPrivateKey,
		Certificate: &cert,
	}
	err = keyring.Add(toAdd)
	if err != nil {
		t.Fatal(err)
	}
	keyList, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keyList) < 1 {
		t.Fatal("invalid Keyring")
	}
	return signer, cert, keyring, nil
}

func TestLoginWihKeyringAgent(t *testing.T) {
	// generate new signer, user key
	// generate new cert
	// generate new keyring (in memory agent) with user cert,key
	// Instantiate new serverAuthenticator, that trusts that signer
	// Instantiate new mux with the two server authenticator ports
	// instantiate new httptest server
	// instantiate new http client
	// instantiate new httptest server with mux.
	// instantiate new sshauthserver with server testserverurl + keyring

	sshSigner, _, sshAgent, err := generateNewTestCertSignerAndAgent(t)
	if err != nil {
		t.Fatal(err)
	}

	signerPub := sshSigner.PublicKey()
	//ssh.MarshalAuthorizedKey(signerPub)
	sa := sshCertAuth.NewAuthenticator(
		[]string{"localhost", "127.0.0.1"},
		[]string{string(ssh.MarshalAuthorizedKey(signerPub))},
	)
	if sa == nil {
		t.Fatal("Did not worked well")
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/getChallenge",
		func(w http.ResponseWriter, r *http.Request) {
			err := sa.CreateChallengeHandler(w, r)
			if err != nil {
				t.Fatal(err)
			}
		},
	)
	serveMux.HandleFunc("/loginWithChallenge",
		func(w http.ResponseWriter, r *http.Request) {
			_, _, _, err := sa.LoginWithChallenge(r)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
			}

		},
	)
	ts := httptest.NewServer(serveMux)
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	a, err := NewAuthenticator(ts.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.DoLoginWithAgent(sshAgent)
	if err != nil {
		t.Fatal(err)
	}
}
