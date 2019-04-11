/*
should run with -ldflags
go test -ldflags=-r=.
*/
package trustSigner_test

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/colligence-io/signServer/trustSigner"
	"io"
	"testing"
)

func TestTrustSigner(t *testing.T) {

	data, err := trustSigner.GetWBInitializeData("test")
	if err != nil {
		t.Fatal("ER : WB Initialize :", err)
	} else {
		t.Log("OK : WB Initialized : Length =", len(data))
	}

	wbData := trustSigner.ConvertToWhiteBox("test", data)

	addresses := make(map[trustSigner.BlockChainType]string)

	for k, v := range trustSigner.BCTypes {
		publicKey, err := trustSigner.GetWBPublicKey(wbData, v)
		if err != nil {
			t.Fatal("ER : Public key :", err)
		}

		addresses[v] = publicKey

		t.Log("OK : PublicKey for", k, ":", publicKey)

		message := make([]byte, 32)

		_, _ = io.ReadFull(rand.Reader, message)

		signatureData, err := trustSigner.GetWBSignatureData(wbData, v, message)
		if err != nil {
			t.Error("ER : Sign Failed :", err)
		} else {
			t.Log("OK : Signature for random message :", hex.EncodeToString(signatureData))
		}
	}

	rData, err := trustSigner.GetWBRecoveryData(wbData, []byte("553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0"))
	if err != nil {
		t.Fatal("ER : Recovery data generation failed", err)
	} else {
		t.Log("OK : Recovery data created :", string(rData))
	}

	recoveredData, err := trustSigner.SetWBRecoveryData("test", []byte("553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0"), rData)

	if err != nil {
		t.Fatal("ER : Recover whitebox failed", err)
	} else {

		wbData := trustSigner.ConvertToWhiteBox("test", recoveredData)

		for k, v := range trustSigner.BCTypes {
			publicKey, err := trustSigner.GetWBPublicKey(wbData, v)
			if err != nil {
				t.Fatal("ER : Public key :", err)
			}

			if addresses[v] == publicKey {
				t.Log("OK : PublicKey for", k, "match")
			} else {
				t.Error("ER : PublicKey for", k, "not match", publicKey)
			}
		}

	}
}
