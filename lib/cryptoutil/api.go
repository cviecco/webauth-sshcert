package cryptoutil

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Returns 32 bytes of random string encoded
// with URL base64 encoding
func GenRandomString() (string, error) {
	return genRandomString()
}

// Given the client parameters, generates a valid ssh signature that
// can be latter used to sing messages back to the server
func WithAgentGenerateChallengeResponseSignature(clientNonce string,
	challenge string,
	agentClient agent.Agent,
	key *agent.Key) (*ssh.Signature, error) {
	return withAgentGenerateChallengeResponseSignature(clientNonce,
		challenge, agentClient, key)
}
