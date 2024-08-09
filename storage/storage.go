package storage

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type Connection struct {
	db *sql.DB
}

// Create a new connection to the database according to the env-values
// You might get an error if the conection is failed
func Connect() (*Connection, error) {
	con := new(Connection)

	log.Printf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("host_db"),
		os.Getenv("port_db"),
		os.Getenv("user_db"),
		os.Getenv("password_db"),
		os.Getenv("dbname_db"),
		os.Getenv("sslmode_db"))

	conninf := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("host_db"),
		os.Getenv("port_db"),
		os.Getenv("user_db"),
		os.Getenv("password_db"),
		os.Getenv("dbname_db"),
		os.Getenv("sslmode_db"))

	db, err := sql.Open("postgres", conninf)
	if err == nil {
		err = db.Ping()
	}
	if err == nil {
		con.db = db
	}
	return con, err
}

// Delete all of clients in the table Clients
func (c *Connection) DeleteCliets() {
	query := "DELETE FROM Clients"
	_, err := c.db.Exec(query)
	if err != nil {
		panic(err)
	}
}

func (c *Connection) RestartSeq() {
	query := "ALTER SEQUENCE clients_id_seq RESTART WITH 1"
	_, err := c.db.Exec(query)
	if err != nil {
		panic(err)
	}
}

func (c *Connection) GetRefreshToken(id int) ([]byte, error) {
	var token []byte
	query := "SELECT refreshtoken FROM Clients WHERE id = $1"
	err := c.db.QueryRow(query, id).Scan(&token)
	return token, err
}

func (c *Connection) SaveRefreshToken(token []byte, id int) error {
	query := "UPDATE Clients SET refreshtoken = $1 WHERE id = $2"
	_, err := c.db.Exec(query, token, id)
	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Code == "23505" {
			err = fmt.Errorf("23505")
		}
	}
	return err
}

func (c *Connection) FindNicknameOrEmail(client *apptype.Client) (bool, bool, error) {
	var email, nickname int
	query := "SELECT COUNT(*) FROM Clients WHERE nickname = $1"
	err := c.db.QueryRow(query, client.Nickname).Scan(&nickname)
	if err == nil {
		query = "SELECT COUNT(*) FROM Clients WHERE email = $1"
		err = c.db.QueryRow(query, client.Email).Scan(&email)
	}
	return nickname == 0, email == 0, err
}

func (c *Connection) CreateNewClient(nickname, email, ip string) int {
	var id int
	query := "INSERT INTO Clients (nickname, email, ip) VALUES ($1, $2, $3)"
	_, err := c.db.Exec(query, nickname, email, ip)
	if err != nil {
		panic(err)
	}
	query = "SELECT id FROM Clients WHERE nickname = $1"
	err = c.db.QueryRow(query, nickname).Scan(&id)
	if err != nil {
		panic(err)
	}
	return id
}

func (c *Connection) CheckId(id int) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM Clients WHERE id = $1"
	err := c.db.QueryRow(query, id).Scan(&count)
	return count == 1, err
}

func (c *Connection) CheckIP(id int, ip string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM Clients WHERE id = $1 AND ip = $2"
	err := c.db.QueryRow(query, id, ip).Scan(&count)
	return count == 1, err
}

func (c *Connection) SelectEmail(id int) (string, error) {
	var email string
	query := "SELECT email FROM Clients WHERE id = $1"
	err := c.db.QueryRow(query, id).Scan(&email)
	return email, err
}
