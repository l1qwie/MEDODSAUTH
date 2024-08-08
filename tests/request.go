package tests

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	api "github.com/l1qwie/MEDODSAUTH/api/rest"
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

func keyFunc(token *jwt.Token) (interface{}, error) {
	_, ok := token.Method.(*jwt.SigningMethodECDSA)
	if !ok {
		panic("No Access-Token in the response")
	}
	return token, nil
}

func getAccessAndRefresh(body []byte) *apptype.DoubleKeys {
	var (
		// acctoken, reftoken   *jwt.Token
		respbody, decodedMes []byte
		req                  *http.Request
		resp                 *http.Response
	)
	doublekey := new(apptype.DoubleKeys)
	client := createClient()
	encodedBody, err := api.Encode(body, apptype.SymKey)
	if err != nil {
		panic(fmt.Sprintf("Coudln't encode body: %s", err))
	}
	req, err = http.NewRequest("GET", "https://localhost:3000/test_login", bytes.NewBuffer(encodedBody))
	req.Header.Set("Content-Type", "application/json")
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
	return doublekey
}

func hashRefreshToken(token []byte) string {
	hashedRefreshToken, err := bcrypt.GenerateFromPassword(token, bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(hashedRefreshToken)
}

func checkAccess(t string) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		panic("The access-token is incorrect")
	}
}

func checkRefreshString(t string) string {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(t)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(t))
	if err != nil {
		panic(err)
	}

	reftoken := string(base64Text)
	claims := make(map[string]interface{})
	parts := strings.Split(reftoken, ".")

	if len(parts) != 3 {
		panic("The refresh-token is incorrect")
	}

	if err := json.Unmarshal([]byte(parts[1]), &claims); err != nil {
		panic("Failed to unmarshal part[1] to claims")
	}

	ip, ok := claims["ip"].(string)
	if !ok {
		panic("ClientIP doesn't exist in the payload part of the have gotten token")

	} else {
		if ip != api.ClientIP {
			panic(fmt.Sprintf("ip != api.ClientIP. Ip = %s and api.ClientIP = %s", ip, api.ClientIP))
		}

	}

	expAt, ok := claims["expAt"].(time.Time)
	if !ok {
		panic("expAt doesn't exist in the payload part of the have gotten token")

	} else {
		if expAt != time.Now().Add(10*time.Hour) {
			panic("The time in the token doesn't compare with the expected time")
		}
	}
	return reftoken
}

func checkAccessToken(sha512Token string) {
	token := jwt.New(jwt.SigningMethodEdDSA)
	claims := token.Claims.(jwt.MapClaims)
	claims["expAt"] = time.Now().Add(10 * time.Minute)
	claims["ip"] = api.ClientIP

	tokenString, err := token.SignedString(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}

	hash := sha512.New()
	hash.Write([]byte(tokenString))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	if sha512Token != hashString {
		panic(fmt.Sprintf("Access-tokens don't match to each other. Just genereted token is: %s and have gotten tokes is: %s", hashString, sha512Token))
	}
}

func checkAccessTokenJWT(t *jwt.Token) {
	claims := t.Claims.(jwt.MapClaims)
	ip, ok := claims["ip"].(string)
	if !ok {
		panic("ClientIP doesn't exist in the payload part of the have gotten token")
	} else {
		if ip != api.ClientIP {
			panic(fmt.Sprintf("ip != api.ClientIP. Ip = %s and api.ClientIP = %s", ip, api.ClientIP))
		}
	}

	expAt, ok := claims["expAt"].(time.Time)
	if !ok {
		panic("expAt doesn't exist in the payload part of the have gotten token")
	} else {
		if expAt != time.Now().Add(10*time.Minute) {
			panic("The time in the token doesn't compare with the expected time")
		}
	}
}

func checkRefreshTokenJWT(t *jwt.Token) {
	claims := t.Claims.(jwt.MapClaims)
	ip, ok := claims["ip"].(string)
	if !ok {
		panic("ClientIP doesn't exist in the payload part of the have gotten token")
	} else {
		if ip != api.ClientIP {
			panic(fmt.Sprintf("ip != api.ClientIP. Ip = %s and api.ClientIP = %s", ip, api.ClientIP))
		}
	}

	expAt, ok := claims["expAt"].(time.Time)
	if !ok {
		panic("expAt doesn't exist in the payload part of the have gotten token")
	} else {
		if expAt != time.Now().Add(10*time.Hour) {
			panic("The time in the token doesn't compare with the expected time")
		}
	}
}

func getAssessAndRefresh(con *storage.Connection) {
	body, err := json.Marshal(&apptype.Client{
		Nickname: "eewsss",
		Email:    "example@gmail.com",
	})
	if err != nil {
		panic(err)
	}

	doubleKeys := getAccessAndRefresh(body)

	checkAccessToken(doubleKeys.Access)
	reftoken := checkRefreshString(doubleKeys.Refresh)

	tokenDB, err := con.GetRefreshTokens("eewsss")
	if err != nil {
		panic(err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(tokenDB), []byte(reftoken)); err != nil {
		panic(fmt.Sprintf("The token in the database doesn't compare to reftoken: %s", reftoken))
	}
}

// Start all of tests that exist in this module
func StartTests() {
	con, err := storage.Connect()
	if err != nil {
		panic(err)
	}

	getAssessAndRefresh(con)
}
