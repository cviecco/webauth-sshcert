package sshcertauth

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

// Authenticator contains all the structures to authenticate using
// we ssh-certs for web.
type Authenticator struct {
	hostnames             []string
	pendingChallenges     map[string]pendingChallengeData
	pendingChallengeMutex sync.Mutex
	caKeys                []string
	caFingerPrints        []string
	dontCheckHostname     bool
}

// ChallengeResponseData is the json struct of the response
// when requesting a challenge from the Server
type ChallengeResponseData struct {
	Challenge                 string   `json:"challenge"`
	AllowedIssuerFingerprints []string `json:"allowed_issuer_fingerprints,omitempty"`
}

// DefaultCreateChallengePath is a well known path that
// is suggested to be used by consumers of this library
// This will be used by default by clients using the client
// library.
const DefaultCreateChallengePath = "/webauth-sshcert/v1/getChallenge"

// DefaultLoginWithChallengePath is a well known path that
// is suggested to be used by consumers of this library
const DefaultLoginWithChallengePath = "/webauth-sshcert/v1/loginWithChallenge"

// FingerprintSHA256 returns the base64 encoding of the sha256 hash
// with the trailing equal sign removed
func FingerprintSHA256(key ssh.PublicKey) string {
	return fingerprintSHA256(key)
}

// NewAuthenticator returns a new Authenticator ready to
// authenticate usres given the hostnames and caKeys.
func NewAuthenticator(hostnames []string, caKeys []string) *Authenticator {
	a := Authenticator{
		hostnames:         hostnames,
		caKeys:            caKeys,
		pendingChallenges: make(map[string]pendingChallengeData),
	}
	a.computeCAFingeprints()
	return &a
}

// CreateChallengeHandler is the function that should be handleded to do
// the server mux in order to create the challenge.
func (a *Authenticator) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) error {
	return a.createChallengeHandler(w, r)

}

// LoginWithChallenge should be attached to the loginwith challenge path,
// it the job of how to keep the session do /do the redirect is dependent on the caller
// This function returns the authenticated username, expiration time of the authentication
func (a *Authenticator) LoginWithChallenge(r *http.Request) (string, time.Time, string, error) {
	return a.loginWithChallenge(r)
}
