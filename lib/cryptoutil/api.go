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

// Validates that the signature of a blob is actually signed by the corresponding certificate
func VerifyChallengeResponseSignature(sshCert *ssh.Certificate,
	signatureFormat string,
	signatureBlob []byte, clientNonce,
	challenge string) error {
	return verifyChallengeResponseSignature(sshCert, signatureFormat, signatureBlob, clientNonce, challenge)
}
