package tests

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/l1qwie/MEDODSAUTH/api"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
	"golang.org/x/crypto/bcrypt"
)

// Create a client for https test-request
func createClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return client
}

// Send a request to the server
func callAccessAndRefreshServer(id int, method, name, reftoken string) *apptype.DoubleKeys {
	var (
		respbody, decodedMes []byte
		req                  *http.Request
		resp                 *http.Response
	)
	doublekey := new(apptype.DoubleKeys)
	client := createClient()

	req, err := http.NewRequest(method, fmt.Sprintf("https://localhost:3000/test/%s/%d", name, id), bytes.NewBuffer(nil))
	req.Header.Set("Content-Type", "application/json")
	if reftoken != "" {
		req.Header.Set("Refresh-Token", reftoken)
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to create a request: %s", err))
	}

	resp, err = client.Do(req)
	if err != nil {
		panic(fmt.Sprintf("Failed to make the request: %s", err))
	}

	defer resp.Body.Close()

	respbody, err = io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Failed to read the response: %s", err))
	}
	decodedMes, err = api.Decode(respbody, apptype.SymKey)
	if err != nil {
		log.Print(string(respbody))
		panic(fmt.Sprintf("Failed to decode the response message: %s", err))
	}
	err = json.Unmarshal(decodedMes, doublekey)
	if err != nil {
		panic(fmt.Sprintf("Couldn't decode []byte to go-stucter: %s", err))
	}
	log.Printf("Response: %+v", doublekey)
	return doublekey
}

// Checke(decode) a refresh token
func checkRefreshString(t string) string {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(t)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(t))
	if err != nil {
		panic(err)
	}
	return string(base64Text)
}

// Make and save in the database a refresh token (base64 hash)
func makeRefreshString(con *storage.Connection, id int, t string) string {
	bcrypted, err := bcrypt.GenerateFromPassword([]byte(t), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	err = con.SaveRefreshToken(bcrypted, id)
	if err != nil {
		panic(err)
	}
	return string(bcrypted)
}

// Check Access-Token if there is the information I've expected
func checkAccessToken(RespToken string) {
	token, err := jwt.Parse(RespToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there was an error in parsing")
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if token == nil && err != nil {
		panic(fmt.Sprint("invalid token ", err))
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		panic("couldn't parse claims")
	}

	ip := claims["ip"].(string)
	if ip != api.ClientIP {
		panic("Client api doesn't match to the expected one")
	}

	expiredAt, ok := claims["expAt"].(float64)
	if !ok {
		panic("couldn't parse expAt")
	}

	expiredAtInt := int64(expiredAt)
	if expiredAtInt != time.Now().Add(30*time.Minute).Unix() {
		panic("token time isn't true")
	}
	log.Print("Access token is OK")
}

// Test PATCH rest point. Expecte 2 new tokens (Access and Refresh).
// Send only an id
func getAccessAndRefreshTest(con *storage.Connection) {
	log.Print("test getAccessAndRefreshTest() has just started")
	defer con.DeleteCliets()
	defer con.RestartSeq()

	id := con.CreateNewClient("example@example.com", "123.32.232.34")

	doubleKeys := callAccessAndRefreshServer(id, "GET", "login", "")

	checkAccessToken(doubleKeys.Access)
	reftoken := checkRefreshString(doubleKeys.Refresh)

	tokenDB, err := con.GetRefreshToken(id)
	if err != nil {
		panic(err)
	}

	if err = bcrypt.CompareHashAndPassword(tokenDB, []byte(reftoken)); err != nil {
		panic(fmt.Sprintf("The token in the database doesn't compare to reftoken: %s", reftoken))
	} else {
		log.Print("Refresh token is OK")
	}
	log.Print("test getAccessAndRefreshTest() has just finished")
}

// Test PATCH rest point. Expecte 2 new tokens (Access and Refresh).
// Send an id and (old) refresh token
func patchAccessByRefreshTest(con *storage.Connection) {
	log.Print("test patchAccessByRefreshTest() has just started")
	defer con.DeleteCliets()
	defer con.RestartSeq()

	id := con.CreateNewClient("example@example.com", "123.32.232.34")
	oldreftoken := makeRefreshString(con, id, "old-refresh-token")

	doublekey := callAccessAndRefreshServer(id, "PATCH", "refresh", oldreftoken)

	checkAccessToken(doublekey.Access)
	newreftoken := checkRefreshString(doublekey.Refresh)

	tokenDB, err := con.GetRefreshToken(id)
	if err != nil {
		panic(err)
	}

	if err = bcrypt.CompareHashAndPassword(tokenDB, []byte(newreftoken)); err != nil {
		panic(fmt.Sprintf("The token in the database doesn't compare to the new reftoken: %s", newreftoken))
	} else {
		log.Print("New refresh token is OK")
	}
	log.Print("test patchAccessByRefreshTest() has just finished")
}

// Start all of tests that exist in this module
func StartTests(con *storage.Connection) {
	con.DeleteCliets()
	con.RestartSeq()

	getAccessAndRefreshTest(con)
	patchAccessByRefreshTest(con)
}
