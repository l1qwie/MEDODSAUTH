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
	"gopkg.in/gomail.v2"
)

const (
	fromemail string = "cogratulationservice@gmail.com"
	subject   string = "!!!WARNING!!!"
)

func HashRefreshToken(token []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(token, bcrypt.MinCost)
}

func CreateAccessTokenSha512(ip string) (string, error) {
	var hashString string
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["expAt"] = time.Now().Add(time.Minute * 30).Unix()
	claims["ip"] = ip
	key := []byte(os.Getenv("JWT_SECRET"))
	tokenString, err := token.SignedString(key)
	if err == nil {
		hash := sha512.New()
		hash.Write([]byte(tokenString))
		hashBytes := hash.Sum(nil)
		hashString = hex.EncodeToString(hashBytes)
	}
	return hashString, err
}

func CreateAccessToken(ip string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["expAt"] = time.Now().Add(30 * time.Minute).Unix()
	claims["ip"] = ip
	key := []byte(os.Getenv("JWT_SECRET"))
	return token.SignedString(key)
}

func checkRefreshToken(con *storage.Connection, id int, token string) error {
	var tokenDB []byte
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(token)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(token))
	if err == nil {
		tokenDB, err = con.GetRefreshToken(id)
		if err == nil {
			err = bcrypt.CompareHashAndPassword(tokenDB, base64Text)
		}
	}
	return err

}

func createAndSaveRefreshToken(con *storage.Connection, id int) (string, error) {
	var (
		encodedString string
		err           error
		bcrypted      []byte
	)
	tryonother := true
	for tryonother {
		reftoken := []byte("Just a Refresh token for a test task")
		bcrypted, err = bcrypt.GenerateFromPassword(reftoken, bcrypt.DefaultCost)
		if err == nil {
			err = con.SaveRefreshToken(bcrypted, id)
			if err != nil {
				if err.Error() != "23505" {
					tryonother = false
				}
			} else {
				tryonother = false
			}
		}
		if err == nil {
			encodedString = base64.StdEncoding.EncodeToString([]byte(reftoken))
		}
	}
	return encodedString, err
}

func sendEmail(con *storage.Connection, id int, ip string) error {
	message := fmt.Sprintf("Someone is trying to sign in in your account from a diffrent device! Their IP is %s. If this is you just ignore the message.", ip)
	to, err := con.SelectEmail(id)
	if err == nil {
		m := gomail.NewMessage()
		m.SetHeader("From", fromemail)
		m.SetHeader("To", to)
		m.SetHeader("Subject", subject)
		m.SetBody("text/html", message)

		d := gomail.NewDialer("smtp.gmail.com", 587, fromemail, "ycuw acml gnor qcir")
		err = d.DialAndSend(m)
	}
	return err
}

func CheckRequestData(con *storage.Connection, id int) error {
	var (
		err error
	)
	ok, err := con.CheckId(id)
	if !ok && err == nil {
		err = fmt.Errorf("the id doesn't exist in the database")
	}
	return err
}

func CreateAccessAndRefreshTokens(createAccess func(string) (string, error), doublekeys *apptype.DoubleKeys, con *storage.Connection, id int, ip string) error {
	var err error
	doublekeys.Access, err = createAccess(ip)
	if err == nil {
		doublekeys.Refresh, err = createAndSaveRefreshToken(con, id)
	}
	return err
}

func CheckIdAndIpAndRefreshToken(con *storage.Connection, id int, ip, token string) error {
	var (
		idOk, ipOk bool
		err        error
	)
	idOk, err = con.CheckId(id)
	if idOk {
		ipOk, err = con.CheckIP(id, ip)
		if ipOk {
			err = checkRefreshToken(con, id, token)
		} else {
			err = sendEmail(con, id, ip)
		}
	} else {
		if err == nil {
			err = fmt.Errorf("the id doesn't exist in the database")
		}
	}
	return err
}
