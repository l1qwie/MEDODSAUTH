package app

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
	"golang.org/x/crypto/bcrypt"
)

func HashRefreshToken(token []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(token, bcrypt.MinCost)
}

func createAccessToken(ip string) (string, error) {
	var hashString string
	token := jwt.New(jwt.SigningMethodEdDSA)
	claims := token.Claims.(jwt.MapClaims)
	claims["expAt"] = time.Now().Add(10 * time.Minute)
	claims["ip"] = ip

	tokenString, err := token.SignedString(os.Getenv("JWT_SECRET"))
	if err == nil {
		hash := sha512.New()
		hash.Write([]byte(tokenString))
		hashBytes := hash.Sum(nil)
		hashString = hex.EncodeToString(hashBytes)
	}

	return hashString, err
}

func createRefToken() (string, error) {
	token := jwt.New(jwt.SigningMethodEdDSA)
	claims := token.Claims.(jwt.MapClaims)
	claims["trashData"] = "kalsdklaskldklasldk;asl;kdkljlaskjkd"
	return token.SignedString(os.Getenv("JWT_SECRET"))
}

func saveRefToken(client *apptype.Client, con *storage.Connection, token, ip string) error {
	bcrypted, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err == nil {
		err = con.SaveRefreshToken(client, bcrypted, ip)
	}
	return err
}

func createAndSaveRefreshToken(client *apptype.Client, con *storage.Connection, ip string) (string, error) {
	var encodedString string

	tokenString, err := createRefToken()
	if err != nil {
		encodedString = base64.StdEncoding.EncodeToString([]byte(tokenString))
	}

	err = saveRefToken(client, con, tokenString, ip)
	return encodedString, err
}

func CheckRequestData(client *apptype.Client, con *storage.Connection, ip string) error {
	var (
		err                 error
		nicknameOk, emailOk bool
	)
	if client.Nickname != "" && client.Email != "" {
		nicknameOk, emailOk, err = con.FindNicknameOrEmail(client)
		if err == nil {
			if !nicknameOk {
				err = fmt.Errorf("the nickname is used by someone else. Try to come up with a diffrent one")
			} else if !emailOk {
				err = fmt.Errorf("the email is used by someone else. Try to come up with a diffrent one")
			} else {
				err = con.CreateNewClient(client, ip)
			}
		}
	}
	return err
}

func CreateAccessAndRefreshTokens(client *apptype.Client, doublekeys *apptype.DoubleKeys, con *storage.Connection, ip string) error {
	var err error
	doublekeys.Access, err = createAccessToken(ip)
	if err == nil {
		doublekeys.Refresh, err = createAndSaveRefreshToken(client, con, ip)
	}
	return err
}
