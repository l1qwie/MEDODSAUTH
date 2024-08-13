package app

import (
	"encoding/base64"
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

// Create an Access (JWT) token
func createAccessToken(ip string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["expAt"] = time.Now().Add(30 * time.Minute).Unix()
	claims["ip"] = ip
	key := []byte(os.Getenv("JWT_SECRET"))
	return token.SignedString(key)
}

// Check a refresh token
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

// Create and save a refresh token
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

// Send a message to client's email
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

// Chech id and if it doesn't exist it will send a error
func CheckRequestData(con *storage.Connection, id int) error {
	var (
		err error
		ok  bool
	)
	ok, err = con.CheckId(id)
	if !ok && err == nil {
		err = fmt.Errorf("the id doesn't exist in the database")
	}
	return err
}

// Create an Access token and a Refresh token
func CreateAccessAndRefreshTokens(doublekeys *apptype.DoubleKeys, con *storage.Connection, id int, ip string) error {
	var err error
	doublekeys.Access, err = createAccessToken(ip)
	if err == nil {
		doublekeys.Refresh, err = createAndSaveRefreshToken(con, id)
	}
	return err
}

// Check an Id, an Ip and a Refresh token.
// If Id is Ok and Refresh token is ok as well,
// but ip isn't match to a previous one this function
// will send a message to the client's email
func CheckIdAndIpAndRefreshToken(con *storage.Connection, id int, ip, token string) error {
	var (
		idOk, ipOk bool
		err        error
	)
	idOk, err = con.CheckId(id)
	if idOk {
		ipOk, err = con.CheckIP(id, ip)
		if ipOk && err == nil {
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
