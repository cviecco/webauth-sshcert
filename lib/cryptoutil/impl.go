package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const randomStringEntropyBytes = 32

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil
}

func withAgentGenerateChallengeResponseSignature(clientNonce string,
	challenge string,
	hostname string,
	agentClient agent.Agent,
	key *agent.Key) (*ssh.Signature, error) {
	pubKey, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, err
	}
	_, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("Not an SSH cert")
	}
	//s.loggerPrintf(2, "cert=%+v", sshCert)

	hash := sha256.Sum256([]byte(clientNonce + hostname + challenge))
	return agentClient.Sign(pubKey, hash[:])
}

func withCertAndPrivateKeyGenerateChallengeResponseSignature(nonce1 string,
	challenge string,
	hostname string,
	certificate *ssh.Certificate,
	privateKey interface{}) (*ssh.Signature, error) {
	keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:  privateKey,
		Certificate: certificate,
	}
	err := keyring.Add(toAdd)
	if err != nil {
		return nil, err
	}
	keyList, err := keyring.List()
	if err != nil {
		return nil, err
	}
	if len(keyList) < 1 {
		return nil, fmt.Errorf("something wrong with keylist")
	}
	return WithAgentGenerateChallengeResponseSignature(nonce1, challenge, hostname, keyring, keyList[0])
}

func verifyChallengeResponseSignature(sshCert *ssh.Certificate, signatureFormat string,
	signatureBlob []byte, clientNonce, challenge, hostname string) error {
	hash := sha256.Sum256([]byte(clientNonce + hostname + challenge))
	signature := &ssh.Signature{
		Format: signatureFormat,
		Blob:   signatureBlob,
	}
	return sshCert.Verify(hash[:], signature)
}
