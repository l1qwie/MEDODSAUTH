package apptype

var SymKey []byte

// Data about a client
type Client struct {
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

type DoubleKeys struct {
	Access  string `json:"access_jwt_key"`
	Refresh string `json:"refresh_jwt_key"`
}
