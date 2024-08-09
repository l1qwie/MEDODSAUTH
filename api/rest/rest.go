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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/l1qwie/MEDODSAUTH/app"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
)

var ClientIP string

type Error struct {
	Err string `json:"error"`
}

func Decode(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce size is incorrect")
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func Encode(data, key []byte) ([]byte, error) {
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

func prepapreResponse(doublekey *apptype.DoubleKeys, statreq *int, encodedBody *[]byte, err error) {
	if err != nil {
		bodyResponse, _ := json.Marshal(&Error{Err: err.Error()})
		*encodedBody, _ = Encode(bodyResponse, apptype.SymKey)
		*statreq = http.StatusBadRequest
	} else {
		bodyResponse, _ := json.Marshal(doublekey)
		*encodedBody, _ = Encode(bodyResponse, apptype.SymKey)
		*statreq = http.StatusOK
	}
}

func GetAccessAndRefreshTokens(ctx *gin.Context, con *storage.Connection, createAccess func(string) (string, error)) {
	log.Print("Got into GetAccessAndRefreshTokens()")
	var (
		statreq     int
		encodedBody []byte
	)
	idstr := ctx.Param("id")
	id, err := strconv.Atoi(idstr)

	doublekey := new(apptype.DoubleKeys)
	if err == nil {
		err = app.CheckRequestData(con, id)
		if err == nil {
			err = app.CreateAccessAndRefreshTokens(createAccess, doublekey, con, id, ctx.ClientIP())
		}
	}
	log.Printf("Intermediate result: id: %d, doublekey: %v, err: %s", id, doublekey, err)

	prepapreResponse(doublekey, &statreq, &encodedBody, err)

	ctx.Data(statreq, "application/json", encodedBody)
	log.Printf("Got out of GetAccessAndRefreshTokens()")
}

func RefreshOperation(ctx *gin.Context, con *storage.Connection, createAccess func(string) (string, error)) {
	log.Print("Got into RefreshOperation()")
	var (
		statreq     int
		encodedBody []byte
	)
	idstr := ctx.Param("id")
	id, err := strconv.Atoi(idstr)
	doublekey := new(apptype.DoubleKeys)
	if err == nil {
		if err == nil {
			token := ctx.Request.Header["Refresh-Token"][0]
			err = app.CheckIdAndIpAndRefreshToken(con, id, ctx.ClientIP(), token)
			if err == nil {
				err = app.CreateAccessAndRefreshTokens(createAccess, doublekey, con, id, ctx.ClientIP())
			}
		}
	}
	log.Printf("Intermediate result: id: %d, doublekey: %v, err: %s", id, doublekey, err)

	prepapreResponse(doublekey, &statreq, &encodedBody, err)

	ctx.Data(statreq, "application/json", encodedBody)
	log.Printf("Got out of GetAccessAndRefreshTokens()")
}
