package storage

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/l1qwie/MEDODSAUTH/apptype"
	_ "github.com/lib/pq"
)

type Connection struct {
	db *sql.DB
}

// Create a new connection to the database according to the env-values
// You might get an error if the conection is failed
func Connect() (*Connection, error) {
	con := new(Connection)
	conninf := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("host_db"),
		os.Getenv("port_db"),
		os.Getenv("user_db"),
		os.Getenv("password_db"),
		os.Getenv("dbname_db"),
		os.Getenv("sslmode_db"))

	db, err := sql.Open("postgres", conninf)
	if err == nil {
		err = con.db.Ping()
	}
	if err == nil {
		con.db = db
	}
	return con, err
}

// Create a client and put his id into client.ID.
// If something go wrong during the querys to the database you'll get an error
func (c *Connection) CreateClient(client *apptype.Client) error {
	query := "INSERT INTO Clients () VALUES ()"
	_, err := c.db.Exec(query, client.FName, client.LName, client.Nickname, client.Email)
	if err == nil {
		query = "SELECT id FROM Clients WHERE nickname = $1"
		err = c.db.QueryRow(query).Scan(&client.ID)
	}
	return err
}

// Delete all of clients in the table Clients
func (c *Connection) DeleteCliets() error {
	query := "DELETE FROM Clients"
	_, err := c.db.Exec(query)
	return err
}

func (c *Connection) GetRefreshTokens(nickname string) (string, error) {
	var token string
	query := "SELECT refreshtoken FROM Clients WHERE nickname = $1"
	err := c.db.QueryRow(query, nickname).Scan(&token)
	return token, err
}

func (c *Connection) SaveRefreshToken(client *apptype.Client, token []byte, ip string) error {
	query := "UPDATE Clients SET refreshtoken = $1 WHERE ip = $2 AND nickname = $3 AND email = $4"
	_, err := c.db.Exec(query, token, ip, client.Nickname, client.Email)
	return err
}

func (c *Connection) FindNicknameOrEmail(client *apptype.Client) (bool, bool, error) {
	var email, nickname int
	query := "SELECT COOUNT(*) FROM Clients WHERE nickname = $1"
	err := c.db.QueryRow(query, client.Nickname).Scan(&nickname)
	if err == nil {
		query = "SELECT COOUNT(*) FROM Clients WHERE email = $1"
		err = c.db.QueryRow(query).Scan(&email)
	}
	return nickname == 0, email == 0, err
}

func (c *Connection) CreateNewClient(client *apptype.Client, ip string) error {
	query := "INSERT INTO Clients (nickname, email, ip) VALUES ($1, $2, $3)"
	_, err := c.db.Exec(query, client.Nickname, client.Email, ip)
	return err
}
