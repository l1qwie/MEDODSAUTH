package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	api "github.com/l1qwie/MEDODSAUTH/api/rest"
	"github.com/l1qwie/MEDODSAUTH/storage"
	"github.com/l1qwie/MEDODSAUTH/tests"
)

func createEnv() *storage.Connection {
	con, err := storage.Connect()
	if err != nil {
		panic(err)
	}
	return con
}

func startServer(con *storage.Connection) {
	router := gin.Default()

	router.GET("login", func(ctx *gin.Context) {
		api.GetAccessAndRefreshTokens(ctx, con)
	})

	router.GET("/test_login", func(ctx *gin.Context) {
		api.ClientIP = ctx.ClientIP()
		api.GetAccessAndRefreshTokens(ctx, con)
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
