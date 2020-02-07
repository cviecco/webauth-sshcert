package sshAutn

import (
	"net/http"
	"net/url"

	"golang.org/x/crypto/ssh/agent"
)

// SSHAuthenticator is the master struct with private fields to handle the authentication
type SSHAuthenticator struct {
	rawBaseURL             string
	client                 *http.Client
	baseURL                *url.URL
	getChallengePath       string
	loginWithChallengePath string
	LogLevel               uint
}

// NewAuthenticator creates a new Authenticator struct for the given client
// and targetURL for authentication.
func NewAuthenticator(baseURL string, client *http.Client) (*SSHAuthenticator, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	a := SSHAuthenticator{
		rawBaseURL: baseURL,
		baseURL:    parsedBaseURL,
		client:     client,
		// TODO: default paths should be defined from server
		getChallengePath:       "/getChallenge",
		loginWithChallengePath: "/loginWithChallenge",
		//pendingChallenges: make(map[string]pendingChallengeData),
	}
	return &a, nil
}

// DoLogin will do the authentication step against an authenticator, will
// return the content and headers of the authentication call. Is it up to
// the implementors to carry the session. It will use the running SSH agent
// and will fail if there is no agent.
func (s *SSHAuthenticator) DoLogin() ([]byte, http.Header, error) {
	return s.loginWithAgentSocket()
}

// DoLoginWithAgent will perform the same as DoLogin, but with an explicit
// ssh agent. This can be used when an actual agent is not exist on the system
func (s *SSHAuthenticator) DoLoginWithAgent(agentClient agent.Agent) ([]byte, http.Header, error) {
	return s.loginWithAgent(agentClient)
}
