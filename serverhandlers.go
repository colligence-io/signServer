package main

import (
	"encoding/hex"
	"github.com/colligence-io/signServer/rr"
	"github.com/colligence-io/signServer/trustSigner"
	"net/http"
)

func signHandler(req *http.Request) rr.ResponseEntity {
	var request struct {
		Type      trustSigner.BlockChainType `json:"type"`
		PublicKey string                     `json:"publicKey"`
		Data      string                     `json:"data"`
	}

	var response struct {
		Signature string `json:"signature"`
	}

	if err := rr.ParseRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	dataToSign, err := hex.DecodeString(request.Data)

	if err != nil {
		return rr.ErrorResponse(err)
	}

	wb, err := getWhiteBoxData(request.Type, request.PublicKey)

	if err != nil {
		return rr.ErrorResponse(err)
	}

	signature := trustSigner.GetWBSignatureData(wb, request.Type, dataToSign)

	response.Signature = hex.EncodeToString(signature)

	return rr.OkResponse(response)
}

func reloadHandler(req *http.Request) rr.ResponseEntity {
	initKeyStore()
	return rr.OkResponse("OK")
}
