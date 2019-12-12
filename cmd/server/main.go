package main

import (
	//"bytes"
	//"bufio"
	"crypto/rand"
	//"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"
	//"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	//"net"
	"net/http"
	"sync"
	"time"

	"github.com/cviecco/webauth-sshcert/lib/server/sshCertAuth"
	//"golang.org/x/crypto/ssh"
)

type AuthCookieStruct struct {
	Username  string
	ExpiresAt time.Time
}

type Server struct {
	authenticator *sshCertAuth.Authenticator
	authCookie    map[string]AuthCookieStruct
	cookieMutex   sync.Mutex
}

var (
	listenAddr = flag.String("addr", "127.0.0.1:4443", "listening Address")
)

const authCookieName = "demo-auth-cookie"
const cookieExpirationHours = 1

const exampleSigner = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD6+x+wPjuKWM7A8aCZgGdiFXRZdpLRZk+KpvNBe9nXu9GHznWYrPIXWVCLl+yp6v30ldzRUiCzHnskV0R4Wzjxi2LCKlVIwpx2Z7gVk8XnZf/MAHdvklfHB2srpWsGUQNJhxCVeOFweJxhLSILkh6y+V0yZ8Zy3t2ALCrHAyOEYhz/RgHgmWMYvxzoSj5wnS16tY3Adt3sOu3DMRq45dIsKjN0bjSPjycL6TQGWvE9BK8HsioyEVCNItWbh4+4kfr4L32U6Sw9syvK4P29kvHnPbSoLssCKuWvtKaLjI9qKFj+sL3hlsZCU5kvHEPVWDudExW2wA8hm6S2wpIOqI/Ua/24Dhm7MKimeqXiOoO0wzPeh7IaKQfczy68Hmk2S8oubj8wIwjxZICbhL/cxl7ZD1EWY/LZH+g5bf98gvl0mC3gFWEVyA4ZZwNkzIlV1NZXibXkdsquJg24/+ZMMtMat/kqd8di9lzuoVRAOV9q80v7QFi25jHjKgXTJ7Av7mc="

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Server) setAndStoreAuthCookie(w http.ResponseWriter, username string) error {
	randomString, err := randomStringGeneration()
	if err != nil {
		log.Println(err)
		return err
	}
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	userCookie := http.Cookie{Name: authCookieName, Value: randomString, Path: "/", Expires: expires, HttpOnly: true, Secure: true}
	http.SetCookie(w, &userCookie)
	Cookieinfo := AuthCookieStruct{username, userCookie.Expires}
	s.cookieMutex.Lock()
	s.authCookie[userCookie.Value] = Cookieinfo
	s.cookieMutex.Unlock()
	return nil
}

func (s *Server) getRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {

	//setupSecurityHeaders(w)

	remoteCookie, err := r.Cookie(authCookieName)
	if err != nil {
		//s.logger.Debugf(1, "Err cookie %s", err)
		http.Error(w, "", http.StatusUnauthorized)
		return "", err
	}
	s.cookieMutex.Lock()
	defer s.cookieMutex.Unlock()
	authInfo, ok := s.authCookie[remoteCookie.Value]
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

func (s *Server) genTokenHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		log.Printf("failure getting username")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	outString := fmt.Sprintf("hello %s\n", authUser)
	io.WriteString(w, outString)
}

func (s *Server) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	err := s.authenticator.CreateChallengeHandler(w, r)
	if err != nil {
		log.Printf("there was an err: %s", err)
	}
}

func (s *Server) LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authUser, userErrString, err := s.authenticator.LoginWithChallenge(r)
	if err != nil {
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		http.Error(w, userErrString, errorCode)
		return
	}
	err = s.setAndStoreAuthCookie(w, authUser)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	log.Printf("Success auth %s", authUser)
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	server := Server{
		authenticator: sshCertAuth.NewAuthenticator([]string{"localhost"}, []string{exampleSigner}),
		authCookie:    make(map[string]AuthCookieStruct),
	}

	http.HandleFunc("/genToken", server.genTokenHandler)
	http.HandleFunc("/getChallenge", server.CreateChallengeHandler)
	http.HandleFunc("/loginWithChallenge", server.LoginWithChallengeHandler)
	err := http.ListenAndServeTLS(*listenAddr, "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
