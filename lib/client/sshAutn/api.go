package sshAutn

import (
	"net/http"
	"net/url"
	//"golang.org/x/crypto/ssh/agent"
)

type SSHAuthenticator struct {
	rawBaseURL             string
	client                 *http.Client
	baseURL                *url.URL
	getChallengePath       string
	loginWithChallengePath string
	LogLevel               uint
	//agentClient agent.ExtendedAgent,
}

type ChallengeResponseData struct {
	Challenge string `json:"challenge"`
}

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

func (s *SSHAuthenticator) DoLogin() error {
	return s.loginWithAgentSocket()
}
