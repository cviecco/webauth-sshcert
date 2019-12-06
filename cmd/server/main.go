package main

import (
	"bytes"
	//"bufio"
	"crypto/rand"
	"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	//"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type challengeResponseData struct {
	Nonce2 string `json:"nonce2"`
}

type pendingChallangeData struct {
	nonce2     string
	cert       *ssh.Certificate
	expiration time.Time
}

type AuthCookieStruct struct {
	Username  string
	ExpiresAt time.Time
}

var (
	pendingChallenges = make(map[string]pendingChallangeData)
	authCookie        = make(map[string]AuthCookieStruct)
	cookieMutex       sync.Mutex
	listenAddr        = flag.String("addr", "127.0.0.1:4443", "listening Address")
)

const authCookieName = "demo-auth-cookie"
const cookieExpirationHours = 1
const exampleSigner = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD6+x+wPjuKWM7A8aCZgGdiFXRZdpLRZk+KpvNBe9nXu9GHznWYrPIXWVCLl+yp6v30ldzRUiCzHnskV0R4Wzjxi2LCKlVIwpx2Z7gVk8XnZf/MAHdvklfHB2srpWsGUQNJhxCVeOFweJxhLSILkh6y+V0yZ8Zy3t2ALCrHAyOEYhz/RgHgmWMYvxzoSj5wnS16tY3Adt3sOu3DMRq45dIsKjN0bjSPjycL6TQGWvE9BK8HsioyEVCNItWbh4+4kfr4L32U6Sw9syvK4P29kvHnPbSoLssCKuWvtKaLjI9qKFj+sL3hlsZCU5kvHEPVWDudExW2wA8hm6S2wpIOqI/Ua/24Dhm7MKimeqXiOoO0wzPeh7IaKQfczy68Hmk2S8oubj8wIwjxZICbhL/cxl7ZD1EWY/LZH+g5bf98gvl0mC3gFWEVyA4ZZwNkzIlV1NZXibXkdsquJg24/+ZMMtMat/kqd8di9lzuoVRAOV9q80v7QFi25jHjKgXTJ7Av7mc="

func isUserAuthority(auth ssh.PublicKey) bool {
	sshCaPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(exampleSigner))
	if err != nil {
		log.Printf("error parsing ssh PubCA", err)
		return false
	}
	return bytes.Equal(sshCaPub.Marshal(), auth.Marshal())

}

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func setAndStoreAuthCookie(w http.ResponseWriter, username string) error {
	randomString, err := randomStringGeneration()
	if err != nil {
		log.Println(err)
		return err
	}
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	userCookie := http.Cookie{Name: authCookieName, Value: randomString, Path: "/", Expires: expires, HttpOnly: true, Secure: true}
	http.SetCookie(w, &userCookie)
	Cookieinfo := AuthCookieStruct{username, userCookie.Expires}
	cookieMutex.Lock()
	authCookie[userCookie.Value] = Cookieinfo
	cookieMutex.Unlock()
	return nil
}

func CreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		//state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		//state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	encodedNonce1 := r.Form.Get("nonce1")
	if encodedNonce1 == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// TODO: validate nonce1 is actually a valid base64 value
	log.Printf("nonce1=%s", encodedNonce1)

	encodedSshCert := r.Form.Get("sshCert")
	if encodedSshCert == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	log.Printf("sshCert=%s", encodedSshCert)
	// TODO: Validate inbound data cert (regexp + size)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedSshCert))
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Printf("it is not a cert")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	log.Printf("pubkey=%+v", sshCert)
	// now we validate the cert
	//verify the cert....
	if len(sshCert.ValidPrincipals) != 1 {
		log.Printf("Too many principals in cert")
		http.Error(w, "Cert has too many principals (or none)", http.StatusBadRequest)
		return
	}
	principal := sshCert.ValidPrincipals[0]

	certChecker := ssh.CertChecker{
		IsUserAuthority: isUserAuthority,
	}
	err = certChecker.CheckCert(principal, sshCert)
	if err != nil {
		log.Printf("failt to checkCert err=%s", err)
		http.Error(w, "Invalid or expired Cert", http.StatusUnauthorized)
		return
	}
	///Now build response
	//nonce2 := "helloNonce"
	nonce2, err := randomStringGeneration()
	if err != nil {
		log.Printf("failure to generate random err=%s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	toStore := pendingChallangeData{
		nonce2: nonce2,
		cert:   sshCert,
	}
	pendingChallenges[encodedNonce1] = toStore

	returnData := challengeResponseData{
		Nonce2: nonce2,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(returnData)
	log.Printf("Challenge Created")

}

func LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		//state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		//state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	encodedNonce1 := r.Form.Get("nonce1")
	if encodedNonce1 == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// TODO: validate nonce1 is actually a valid base64 value
	log.Printf("nonce1=%s", encodedNonce1)

	signatureFormat := r.Form.Get("signatureFormat")
	if signatureFormat == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// TODO: validate the signature format is sane
	log.Printf("signatureFormat=%s", signatureFormat)

	encodedSignatureBlob := r.Form.Get("signatureBlob")
	if encodedSignatureBlob == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	signatureBlob, err := base64.URLEncoding.DecodeString(encodedSignatureBlob)
	if err != nil {
		http.Error(w, "Invalid Signature Data", http.StatusBadRequest)
		return
	}
	challengeData, ok := pendingChallenges[encodedNonce1]
	if !ok {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256([]byte(encodedNonce1 + challengeData.nonce2))
	signature2 := &ssh.Signature{
		Format: signatureFormat,
		Blob:   signatureBlob,
	}
	err = challengeData.cert.Verify(hash[:], signature2)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	authUser := challengeData.cert.ValidPrincipals[0]
	err = setAndStoreAuthCookie(w, authUser)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	log.Printf("Success auth %s", authUser)
}

func getRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {

	//setupSecurityHeaders(w)

	remoteCookie, err := r.Cookie(authCookieName)
	if err != nil {
		//s.logger.Debugf(1, "Err cookie %s", err)
		http.Error(w, "", http.StatusUnauthorized)
		return "", err
	}
	cookieMutex.Lock()
	defer cookieMutex.Unlock()
	authInfo, ok := authCookie[remoteCookie.Value]
	if !ok {
		//s.oauth2DoRedirectoToProviderHandler(w, r)
		http.Error(w, "", http.StatusUnauthorized)
		return "", fmt.Errorf("Cookie not found")
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		//s.oauth2DoRedirectoToProviderHandler(w, r)
		http.Error(w, "", http.StatusUnauthorized)
		return "", fmt.Errorf("Expired Cookie")
	}
	return authInfo.Username, nil
}

func genTokenHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := getRemoteUserName(w, r)
	if err != nil {
		log.Printf("failure getting username")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	outString := fmt.Sprintf("hello %s\n", authUser)
	io.WriteString(w, outString)
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
	// fmt.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	http.HandleFunc("/hello", HelloServer)
	http.HandleFunc("/genToken", genTokenHandler)
	http.HandleFunc("/getChallenge", CreateChallengeHandler)
	http.HandleFunc("/loginWithChallenge", LoginWithChallengeHandler)
	err := http.ListenAndServeTLS(*listenAddr, "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
