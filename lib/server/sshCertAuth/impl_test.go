package sshCertAuth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

//  ssh-keygen -f /tmp/deleteme_rsa
const testUserPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvJq2TMC6oSj7Y+xXBS+L4JnHtrjSEqIaAMTda/2HldiQSaVF
wiNC6TihJqOek9UGNmNJbpezJcvbM6t7cssyRr1EkaU5NJ+6YpUFCLLJMOjRJ7ce
fak4Rf6GabC5SSMa8qth1qEcdJbwJi9sgbTNpMxM6GBQLkjXvefvC+pInNAYORnF
lnr3JJDMJd/EbVQb2LHcACwelbyo6VeR2NSxDwHcQ6rXUd36pRKSAfR8FBtqShmi
OLaHHec0NBBj1S0WnAaLdk38rHjAZtOPuyzqNGkm/8mnwHWGNnr+G6Werer2ij/9
JpbJ8Ee38yBCJ+HBpzILyup2bxsM9/8uhss6HwIDAQABAoIBAByCurohjFTecBor
2P/Erz11obYifEcq0Al7uQkhG0TwpucrH794Ox4sXFgN9ePdGQJRwgEA16kIBwvp
iVDSHLiK1fm6Y0psNu2+HzOway+EklGRof9W/FXAYytI9slykBlNBQ4/7qBFTOpI
0vtMjKWz6JBcNuK4Sjy/+efwM6fYnsxnyi30rtj8iv4YTzepO46b9KiIc4ByhVgd
UbK1quHQTk+dIlVSQaJCssGftLoyB9jqfLfOSkMOze6TSJwXXSTJ4Wz0Y5xGMOEZ
4l8xa/E4o69J5GOpWdV95ieiCkEt8DqFoNg0FgHB785CvgBFeVVczLNYUooRTzsT
EoPuudECgYEA4VPi0+lxMNdvFyHNeoyc8FI2doZUxKbnlrFRpLzPo2Sm8kVl9d+O
PkJ5uStT106Z0+1Y5y2MHArnfdErGl2dN2LIoLlCkufJfSKxq8LXgs8NZYUjZDB5
aC7lSnUzOP1cvM+MQ3ZZ35tRIYYFtIYh/oZypER4fLnJmN3fnP7R6gcCgYEA1kcb
vrMWn1EZ2ihlJoDPeuktw+JCVE1oQ1MqB6wsZJRwDFZLpvVH4a9pZ12Ag9p+qpIh
W2aqgcdjbjRaB1uafHvbiY6qf1PsMLSLOrAqvO/FG/KpruOIhVFDLUrqWdLDXlVI
UtKOQVccBAKGK+CocEnAuHqpVA/QmyMHx7fZiSkCgYEArMn3FynccufBeKujNma9
skxZF2rLdkHHNfej9AAV+eYlX4N4PKPCIFw5m5VuJZ1QuQM5OY3j810pR4Iu23kO
JnrJ/vYR5zV3fU4tkNlJCjZcv4zpJttFPm83xXE6ZmljxCYkGVeYc7BW9q4fkd+K
EfRn1S/sdTjDL0Z1Q57kueECgYEAt1F2hxuoCvzTZTSR9PLWjozXPnJf1Me0n4SS
vKWsBRCJG8ToTBokOQxc3LW9sRBItZz3NL8MuKLgifP34buY208Lbw/DBdPCiZis
VLVKmwF2XIaqbJj0vznagvFItTf/NME5csH4OiZQLY4LQ5acBBTU7/7gxq4RBehe
S5saXKECgYEAwe39pvRbkMA353uNHf2Dkj4STrJGbnc/SuritI3J5H3BfGkGmovG
M58D6oPPabTf/LGfl3089j9AmOyA1aUqoCqSKiAb4DrrpzQndYsxjumD0plHM35X
h12wHUZrzYUWojD0c7UbP8jJAACJkfREFhUQVdrY1xTvlD46Zd91NIE=
-----END RSA PRIVATE KEY-----`

// actual output SHA256:1sTu4EM0wYab///MibgBWdN20XNHAVc2v9ChbJNUWqc cviecco@XXXXXX
const expectedFP = `1sTu4EM0wYab///MibgBWdN20XNHAVc2v9ChbJNUWqc`

// Copied from keymaster's lib/certutil
func getSignerFromPEMBytes(privateKey []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err := fmt.Errorf("Cannot decode Private Key")
		return nil, err
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsedIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch v := parsedIface.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case *ecdsa.PrivateKey:
			return v, nil
		default:
			return nil, fmt.Errorf("Type not recognized  %T!\n", v)
		}
	default:
		err := fmt.Errorf("Cannot process that key")
		return nil, err
	}
}

func TestFingerprintSHA256(t *testing.T) {
	signer, err := getSignerFromPEMBytes([]byte(testUserPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	computedFP := FingerprintSHA256(sshSigner.PublicKey())
	if computedFP != expectedFP {
		t.Fatalf("expected does not match expacted=%s, computed=%s", expectedFP, computedFP)
	}

}
