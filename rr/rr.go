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

/*
Response Handler
*/
type RequestHandler func(req *http.Request) ResponseEntity

func WrapHandler(handler RequestHandler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		res := handler(req)
		resBytes, err := json.Marshal(res)
		if err != nil {
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Println("cannot marshal data")
			return
		}

		rw.WriteHeader(res.Code)

		if _, err := rw.Write(resBytes); err != nil {
			log.Println("cannot write to response")
		}
	}
}

func ParseRequestBody(req *http.Request, body interface{}) error {
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
