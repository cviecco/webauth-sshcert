package sshCertAuth

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type pendingChallengeData struct {
	Nonce1     string
	Cert       *ssh.Certificate
	Expiration time.Time
}

type Authenticator struct {
	hostnames             []string
	pendingChallenges     map[string]pendingChallengeData
	pendingChallengeMutex sync.Mutex
	caKeys                []string
	caFingerPrints        []string
	dontCheckHostname     bool
}

type ChallengeResponseData struct {
	Challenge                 string   `json:"challenge"`
	AllowedIssuerFingerprints []string `json:"allowed_issuer_fingerprints,omitempty"`
}

// base64 sha256 hash with the trailing equal sign removed
func FingerprintSHA256(key ssh.PublicKey) string {
	return fingerprintSHA256(key)
}

func NewAuthenticator(hostnames []string, caKeys []string) *Authenticator {
	a := Authenticator{
		hostnames:         hostnames,
		caKeys:            caKeys,
		pendingChallenges: make(map[string]pendingChallengeData),
	}
	a.computeCAFingeprints()
	return &a
}

func (a *Authenticator) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) error {
	return a.createChallengeHandler(w, r)

}

func (a *Authenticator) LoginWithChallenge(r *http.Request) (string, time.Time, string, error) {
	return a.loginWithChallenge(r)
}
