package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenRandomString(t *testing.T) {
	val1, err := GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	val2, err := GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	//now do trivial test
	if val1 == val2 {
		t.Fatal("not random they are the same!")
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	hostname, err := GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	signerPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(signerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	t.Logf("userPub is %T", userPub)
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}

	cert := ssh.Certificate{
		Key:          sshPub,
		CertType:     ssh.UserCert,
		SignatureKey: signer.PublicKey(),
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := WithCertAndPrivateKeyGenerateChallengeResponseSignature(nonce,
		challenge,
		hostname,
		&cert,
		userPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyChallengeResponseSignature(&cert, signature.Format, signature.Blob, nonce, challenge, hostname)
	if err != nil {
		t.Fatal(err)
	}
	//now we use an invalid blob
	brokenBlob := signature.Blob
	brokenBlob[0] = brokenBlob[0] ^ 0101
	err = VerifyChallengeResponseSignature(&cert, signature.Format, brokenBlob, nonce, challenge, hostname)
	if err == nil {
		t.Fatal(err)
	}
	// now with an incorrect hostname on validation
	err = VerifyChallengeResponseSignature(&cert, signature.Format, signature.Blob, nonce, challenge, "some hostname")
	if err == nil {
		t.Fatal("should not have validated invalid hostname")
	}

}
