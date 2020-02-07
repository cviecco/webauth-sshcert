package cryptoutil

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// GenRandomString returns 32 bytes of random string encoded
// with URL base64 encoding
func GenRandomString() (string, error) {
	return genRandomString()
}

// WithAgentGenerateChallengeResponseSignature generates,
// given the client parameters, a valid ssh signature that
// can be latter used to sing messages back to the server
func WithAgentGenerateChallengeResponseSignature(clientNonce string,
	challenge string,
	hostname string,
	agentClient agent.Agent,
	key *agent.Key) (*ssh.Signature, error) {
	return withAgentGenerateChallengeResponseSignature(clientNonce,
		challenge, hostname, agentClient, key)
}

// WithCertAndPrivateKeyGenerateChallengeResponseSignature generates
// similar to WithAgentGenerateChallengeResponseSignature but instead
// of an agent uses an explicit certifiate and keu
func WithCertAndPrivateKeyGenerateChallengeResponseSignature(nonce1 string,
	challenge string,
	hostname string,
	certificate *ssh.Certificate,
	privateKey interface{}) (*ssh.Signature, error) {
	return withCertAndPrivateKeyGenerateChallengeResponseSignature(nonce1,
		challenge,
		hostname,
		certificate, privateKey)
}

// VerifyChallengeResponseSignature validates that the signature of a blob is
// actually signed by the corresponding certificate. Does NOT do and checks
// on the certificate.
func VerifyChallengeResponseSignature(sshCert *ssh.Certificate,
	signatureFormat string,
	signatureBlob []byte, clientNonce,
	challenge string,
	hostname string) error {
	return verifyChallengeResponseSignature(sshCert, signatureFormat, signatureBlob, clientNonce, challenge, hostname)
}
