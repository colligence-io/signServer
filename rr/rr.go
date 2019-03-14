package rr

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

/*
ResponseEntity
*/

type ResponseEntity struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var UnauthorizedResponse = KoResponse(http.StatusUnauthorized, "I don't know who you are")

var InternalServerErrorResponse = KoResponse(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))

func ErrorResponse(err error) ResponseEntity {
	return KoResponse(http.StatusInternalServerError, err.Error())
}

func KoResponse(statusCode int, message string) ResponseEntity {
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return ResponseEntity{Code: statusCode, Message: message, Data: nil}
}

func OkResponse(data interface{}) ResponseEntity {
	return ResponseEntity{Code: http.StatusOK, Message: "OK", Data: data}
}

func WriteResponseEntity(rw http.ResponseWriter, entity ResponseEntity) {
	resBytes, err := json.Marshal(entity)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Println("cannot marshal data")
		return
	}

	rw.WriteHeader(entity.Code)

	if _, err := rw.Write(resBytes); err != nil {
		log.Println("cannot write to response")
	}
}

func ReadRequestBody(req *http.Request, body interface{}) error {
	bytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, body)
	if err != nil {
		return err
	}
	return nil
}
