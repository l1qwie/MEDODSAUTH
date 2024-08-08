package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/l1qwie/MEDODSAUTH/app"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
)

var ClientIP string

type Error struct {
	Err string `json:"error"`
}

// Шифрует данные отправляемые на сервер
func Encode(data, key []byte) ([]byte, error) {
	var (
		gcm                       cipher.AEAD
		nonceSize                 int
		ciphertext, nonce, result []byte
	)

	block, err := aes.NewCipher(key)
	if err == nil {
		gcm, err = cipher.NewGCM(block)
	}

	if err == nil {
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			err = fmt.Errorf("ciphertext too short")
		}
	}

	if err == nil {
		nonce, ciphertext = data[:nonceSize], data[nonceSize:]
		if len(nonce) != nonceSize {
			err = fmt.Errorf("nonce size is incorrect")
		}
	}

	if err == nil {
		result, err = gcm.Open(nil, nonce, ciphertext, nil)
	}

	return result, err
}

// Расшифровка данных полученных от сервера
func Decode(data, key []byte) ([]byte, error) {
	var (
		gcm           cipher.AEAD
		nonce, result []byte
	)

	block, err := aes.NewCipher(key)
	if err == nil {
		gcm, err = cipher.NewGCM(block)
	}

	if err == nil {
		nonce = make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
	}

	if err == nil {
		result = gcm.Seal(nonce, nonce, data, nil)
	}

	return result, err
}

func GetAccessAndRefreshTokens(ctx *gin.Context, con *storage.Connection) {
	log.Printf("Got into GetAccessAndRefreshTokens() with params\nctx *gin.Context: %v\ncon *storage.Connection: %v", ctx, con)
	var (
		statreq                               int
		decodedMes, bodyResponse, encodedBody []byte
	)
	client := new(apptype.Client)
	doublekey := new(apptype.DoubleKeys)
	respbody, err := io.ReadAll(ctx.Request.Body)
	if err == nil {
		decodedMes, err = Decode(respbody, apptype.SymKey)
		if err == nil {
			err = json.Unmarshal(decodedMes, client)
		}
	}
	if err == nil {
		err = app.CheckRequestData(client, con, ctx.ClientIP())
		if err == nil {
			err = app.CreateAccessAndRefreshTokens(client, doublekey, con, ctx.ClientIP())
		}
	}

	if err != nil {
		bodyResponse, _ = json.Marshal(&Error{Err: err.Error()})
		encodedBody, _ = Encode(bodyResponse, apptype.SymKey)
		statreq = http.StatusBadRequest
	} else {
		bodyResponse, _ = json.Marshal(doublekey)
		encodedBody, _ = Encode(bodyResponse, apptype.SymKey)
		statreq = http.StatusOK
	}

	ctx.Data(statreq, "application/json", encodedBody)
	log.Printf("Got out of GetAccessAndRefreshTokens()")
}
