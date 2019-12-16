package sshCertAuth

import (
	"bytes"
	//"bufio"
	"crypto/rand"
	"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"io"
	"log"
	//"net"
	"net/http"
	//"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// TODO: Marshal auth only once
// TODO: Marshal ca's just once
// TODO: remember most recenly successful ones and try those first.
func (a *Authenticator) isUserAuthority(auth ssh.PublicKey) bool {
	for _, signer := range a.caKeys {
		sshCaPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer))
		if err != nil {
			log.Printf("error parsing ssh PubCA", err)
			continue
		}
		if bytes.Equal(sshCaPub.Marshal(), auth.Marshal()) {
			return true
		}
	}
	return false
}

func (a *Authenticator) createChallengeHandler(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
		return fmt.Errorf("Method not Allowed")
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusBadRequest)
		return err
	}
	encodedNonce1 := r.Form.Get("nonce1")
	if encodedNonce1 == "" {
		http.Error(w, "", http.StatusBadRequest)
		return fmt.Errorf("Missing Parameter (Nonce1)")
	}
	// TODO: validate nonce1 is actually a valid base64 value
	//log.Printf("nonce1=%s", encodedNonce1)

	encodedSshCert := r.Form.Get("sshCert")
	if encodedSshCert == "" {
		http.Error(w, "", http.StatusBadRequest)
		return fmt.Errorf("Missing Parameter (sshCert)")
	}
	//log.Printf("sshCert=%s", encodedSshCert)
	// TODO: Validate inbound data cert (regexp + size)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedSshCert))
	if err != nil {
		log.Printf("sshCert=%s", encodedSshCert)
		log.Println(err)
		http.Error(w, "", http.StatusBadRequest)
		return fmt.Errorf("Invalid Ssh Cert (not valid ssh)")
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Printf("it is not a cert")
		http.Error(w, "", http.StatusBadRequest)
		return fmt.Errorf("This is a key, not a cert")
	}
	//log.Printf("pubkey=%+v", sshCert)
	// now we validate the cert
	//verify the cert....
	if len(sshCert.ValidPrincipals) != 1 {
		log.Printf("Too many principals in cert")
		http.Error(w, "Cert has too many principals (or none)", http.StatusBadRequest)
		return fmt.Errorf("Number of principals in cert != 1")
	}
	principal := sshCert.ValidPrincipals[0]

	certChecker := ssh.CertChecker{
		IsUserAuthority: a.isUserAuthority,
	}
	err = certChecker.CheckCert(principal, sshCert)
	if err != nil {
		log.Printf("failt to checkCert err=%s", err)
		http.Error(w, "Invalid or expired Cert", http.StatusUnauthorized)
		return fmt.Errorf("Invalid or expired Cert")
	}
	///Now build response
	challenge, err := randomStringGeneration()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return err
	}
	toStore := pendingChallengeData{
		Nonce1: encodedNonce1,
		Cert:   sshCert,
	}
	a.pendingChallengeMutex.Lock()
	a.pendingChallenges[challenge] = toStore
	a.pendingChallengeMutex.Unlock()

	returnData := ChallengeResponseData{
		Challenge: challenge,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(returnData)
	//log.Printf("Challenge Created")
	return nil
}
func (a *Authenticator) verifyHostname(hostname string) (bool, error) {
	for _, configuredHostname := range a.hostnames {
		if hostname == configuredHostname {
			return true, nil
		}
	}
	return false, nil
}

func (a *Authenticator) loginWithChallenge(r *http.Request) (string, time.Time, string, error) {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		return "", time.Time{}, "Invalid Method", fmt.Errorf("method not allowed")
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		//state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "", err
	}
	encodedNonce2 := r.Form.Get("challenge")
	if encodedNonce2 == "" {
		return "", time.Time{}, "Missing parameter challenge", fmt.Errorf("Missing parameter challenge")

	}
	// TODO: validate nonce1 is actually a valid base64 value
	log.Printf("nonce2=%s", encodedNonce2)
	hostname := r.Form.Get("hostname")
	if hostname == "" {
		return "", time.Time{}, "Missing parameter hostname", fmt.Errorf("Missing parameter hostname")

	}
	// TODO: validate nonce1 is actually a valid base64 value
	log.Printf("hostname=%s", hostname)
	valid, err := a.verifyHostname(hostname)
	if err != nil {
		return "", time.Time{}, "", err
	}
	if !valid {
		return "", time.Time{}, "Invalid hostname", fmt.Errorf("Invalid hostname")
	}

	signatureFormat := r.Form.Get("signatureFormat")
	if signatureFormat == "" {
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing parameter signatureFormat", fmt.Errorf("Missing parameter signatureFormat")
	}
	// TODO: validate the signature format is sane
	log.Printf("signatureFormat=%s", signatureFormat)
	encodedSignatureBlob := r.Form.Get("signatureBlob")
	if encodedSignatureBlob == "" {
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing parameter signatureBlob", fmt.Errorf("Missing parameter signatureBlob")
	}
	signatureBlob, err := base64.URLEncoding.DecodeString(encodedSignatureBlob)
	if err != nil {
		//http.Error(w, "Invalid Signature Data", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing bad signature Format", err
	}

	a.pendingChallengeMutex.Lock()
	challengeData, ok := a.pendingChallenges[encodedNonce2]
	a.pendingChallengeMutex.Unlock()
	if !ok {
		log.Printf("challenge not found")
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Challenge not found/invalid", fmt.Errorf("Challenge Not Found")
	}

	if challengeData.Expiration.After(time.Now()) {
		log.Printf("Expired Challenge")
		a.pendingChallengeMutex.Lock()
		delete(a.pendingChallenges, encodedNonce2)
		a.pendingChallengeMutex.Unlock()
		return "", time.Time{}, "Challenge expired", fmt.Errorf("Expired Challenge Found")
	}

	hash := sha256.Sum256([]byte(challengeData.Nonce1 + encodedNonce2))
	signature2 := &ssh.Signature{
		Format: signatureFormat,
		Blob:   signatureBlob,
	}
	err = challengeData.Cert.Verify(hash[:], signature2)
	if err != nil {
		log.Println(err)
		//http.Error(w, "", http.StatusUnauthorized)
		return "", time.Time{}, "Unauthorized", fmt.Errorf("Invalid signature %s", err)
	}

	//we have checked before this exists
	authUser := challengeData.Cert.ValidPrincipals[0]

	// TODO check for certificates too far away in the future
	authExpiration := time.Unix(int64(challengeData.Cert.ValidBefore), 0)
	maxAge := time.Now().Add(time.Duration(24) * time.Hour)
	if authExpiration.After(maxAge) {
		authExpiration = maxAge
	}
	return authUser, authExpiration, "", nil
}
