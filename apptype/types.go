package apptype

var SymKey []byte

type DoubleKeys struct {
	Access  string `json:"access_jwt_key"`
	Refresh string `json:"refresh_jwt_key"`
}
