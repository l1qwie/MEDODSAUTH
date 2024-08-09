package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	api "github.com/l1qwie/MEDODSAUTH/api/rest"
	"github.com/l1qwie/MEDODSAUTH/app"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
	"github.com/l1qwie/MEDODSAUTH/tests"
)

func createEnv() *storage.Connection {
	var err error
	apptype.SymKey, err = os.ReadFile("keys/symmetric-key.bin")
	if err != nil {
		panic(err)
	}
	con, err := storage.Connect()
	if err != nil {
		panic(err)
	}
	return con
}

func startServer(con *storage.Connection) {
	router := gin.Default()

	router.GET("/login/hash/usual/:id", func(ctx *gin.Context) {
		api.GetAccessAndRefreshTokens(ctx, con, app.CreateAccessToken)
	})

	router.GET("/login/hash/sha512/:id", func(ctx *gin.Context) {
		api.GetAccessAndRefreshTokens(ctx, con, app.CreateAccessTokenSha512)
	})

	router.GET("/test_login/hash/usual/:id", func(ctx *gin.Context) {
		api.ClientIP = ctx.ClientIP()
		api.GetAccessAndRefreshTokens(ctx, con, app.CreateAccessToken)
	})

	router.PATCH("/test_refresh/hash/usual/:id", func(ctx *gin.Context) {
		api.ClientIP = ctx.ClientIP()
		api.RefreshOperation(ctx, con, app.CreateAccessToken)
	})

	certFile := "keys/server.crt"
	keyFile := "keys/server.key"

	log.Print("Starting HTTPS server on :3000")
	err := router.RunTLS(":3000", certFile, keyFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to start HTTPS server: %v", err))
	}
}

func main() {
	con := createEnv()

	go startServer(con)
	tests.StartTests()
}
