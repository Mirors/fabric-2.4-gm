package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"testing"
)

func TestInstanceCreate(t *testing.T) {

	t.Parallel()

	//fullCmd := kingpin.MustParse(app.Parse(os.Args[1:]))
	//
	//// "version" command
	//if fullCmd == version.FullCommand() {
	//	fmt.Println(metadata.GetVersionInfo())
	//	return
	//}

	conf, err := localconfig.Load()
	if err != nil {
		logger.Error("failed to parse config: ", err)
		os.Exit(1)
	}
	cryptoProvider := factory.GetDefault()

	signer, signErr := LoadLocalMSP(conf).GetDefaultSigningIdentity()

	cryptoProvider = factory.GetDefault()
	print("signer info:")
	println(signer)

	if signErr != nil {
		logger.Panicf("Failed to get local MSP identity: %s", signErr)
	}
	msg := []byte("Test Hash Interface")
	out1, _ := cryptoProvider.Hash(msg, nil)
	print("hashValue:")
	println(out1)
	hash := sha256.New()
	hash.Write(msg)
	out2 := hash.Sum(nil)
	//hr1, _ := cryptoProvider.GetHash(nil)
	print("hashValue:")
	println(out2)
	//require.Equal(t, hr1, sha256.New())

	interMsg, err := signer.Sign(msg)
	print("interMsg:")
	println(interMsg)
	require.NoError(t, err)
	require.NotNil(t, interMsg)
	err = signer.Verify(msg, interMsg)
	require.NoError(t, err)

	//加解密
}

func readPrivateKey(file string) *ecdsa.PrivateKey {

	privBytes, _ := ioutil.ReadFile(file)
	blkPriv, _ := pem.Decode(privBytes)
	key, _ := x509.ParsePKCS8PrivateKey(blkPriv.Bytes)
	ecdsaKey := key.(*ecdsa.PrivateKey)

	return ecdsaKey

}

func TestReadPrivateKey(t *testing.T) {

	t.Parallel()

	msg := "test private key1"
	hash := sha256.Sum256([]byte(msg))
	msg2 := "test private key2"
	hash2 := sha256.Sum256([]byte(msg2))
	//privBytes, _ := ioutil.ReadFile("D:/GoWorks/src/fabric2.4/dev-network/orderer/msp/keystore/priv_sk")
	//blkPriv, _ := pem.Decode(privBytes)
	//key, _ := x509.ParsePKCS8PrivateKey(blkPriv.Bytes)
	ecdsaKey := readPrivateKey("D:/GoWorks/src/fabric2.4/dev-network/orderer/msp/keystore/priv_sk")
	r, s, _ := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	print("r:")
	println(r)
	print("s:")
	println(s)

	certBytes, _ := ioutil.ReadFile("D:/GoWorks/src/fabric2.4/dev-network/orderer/msp/signcerts/orderer.example.com-cert.pem")
	blkCert, _ := pem.Decode(certBytes)
	cert, _ := x509.ParseCertificate(blkCert.Bytes)
	pubkey := cert.PublicKey.(*ecdsa.PublicKey)
	ok := ecdsa.Verify(pubkey, hash[:], r, s)
	fmt.Println("verify hash(shoule be true):", ok)
	ok = ecdsa.Verify(pubkey, hash2[:], r, s)
	fmt.Println("verify hash2(shoule be false):", ok)
}
