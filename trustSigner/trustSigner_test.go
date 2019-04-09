/*
should run with -ldflags
go test -ldflags=-r=.
*/
package trustSigner_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	"io"
	"testing"
)

func TestTS(t *testing.T) {

	data := trustSigner.GetWBInitializeData("test")

	fmt.Println("WB Initialized : Length =", len(data))
	fmt.Println()

	wbData := trustSigner.ConvertToWhiteBox("test", data)

	for k, v := range trustSigner.BCTypes {
		publicKey := trustSigner.GetWBPublicKey(wbData, v)
		fmt.Println("PublicKey for", k, ":", publicKey)
		fmt.Println()

		message := make([]byte, 64)

		//message[32] = '1'

		_, _ = io.ReadFull(rand.Reader, message)

		signatureData, err := trustSigner.GetWBSignatureData(wbData, v, message)
		if err != nil {
			fmt.Println("Sign Failed : ", err)
		} else {
			fmt.Println("Signature for 'message' : ", hex.EncodeToString(signatureData))
			fmt.Println()
		}
	}
}
