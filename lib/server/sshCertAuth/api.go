package sshCertAuth

import (
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

type pendingChallengeData struct {
	Nonce1     string
	Cert       *ssh.Certificate
	Expiration time.Time
}

type Authenticator struct {
	hostnames         []string
	pendingChallenges map[string]pendingChallengeData
	caKeys            []string
	dontCheckHostname bool
}

type ChallengeResponseData struct {
	Challenge string `json:"challenge"`
}

func NewAuthenticator(hostnames []string, caKeys []string) *Authenticator {
	a := Authenticator{
		hostnames:         hostnames,
		caKeys:            caKeys,
		pendingChallenges: make(map[string]pendingChallengeData),
	}
	return &a
}

func (a *Authenticator) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) error {
	return a.createChallengeHandler(w, r)

}

func (a *Authenticator) LoginWithChallenge(r *http.Request) (string, string, error) {
	return a.loginWithChallenge(r)
}
