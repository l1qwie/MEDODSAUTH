package apptype

var SymKey []byte

// Data about a client
type Client struct {
	ID       int    `json:"id"`
	FName    string `json:"first_name"`
	LName    string `json:"last_name"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

type DoubleKeys struct {
	Access  string `json:"access_jwt_key"`
	Refresh string `json:"refresh_jwt_key"`
}
