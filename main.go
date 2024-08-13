package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/l1qwie/MEDODSAUTH/api"
	"github.com/l1qwie/MEDODSAUTH/apptype"
	"github.com/l1qwie/MEDODSAUTH/storage"
	"github.com/l1qwie/MEDODSAUTH/tests"
)

// Create environment like a connection to the database
// and get the symmetric key from the specific file to a go value
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

// Start the server. Four rest points and only two of them for testing
func startServer(con *storage.Connection) *gin.Engine {
	router := gin.Default()

	router.GET("/login/:id", func(ctx *gin.Context) {
		api.GetAccessAndRefreshTokens(ctx, con)
	})
	router.PATCH("/refresh/:id", func(ctx *gin.Context) {
		api.RefreshOperation(ctx, con)
	})

	router.GET("/test/login/:id", func(ctx *gin.Context) {
		api.ClientIP = ctx.ClientIP()
		api.GetAccessAndRefreshTokens(ctx, con)
	})
	router.PATCH("/test/refresh/:id", func(ctx *gin.Context) {
		api.ClientIP = ctx.ClientIP()
		api.RefreshOperation(ctx, con)
	})

	certFile := "keys/server.crt"
	keyFile := "keys/server.key"

	log.Print("Starting HTTPS server on :3000")
	err := router.RunTLS(":3000", certFile, keyFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to start HTTPS server: %v", err))
	}
	return router
}

// Start all tests
func startTests(con *storage.Connection) {
	go startServer(con)
	tests.StartTests(con)
}

func main() {
	con := createEnv()

	// There are 2 tests to check 2 rest points.
	// You must turn it on only if you've already turned startServer(con) and con.CreateMokData() off
	// To turn those two functions off just comment them
	// startTests(con)

	// Here are 2 functions for a real using. If you want to use my program as a real program, not a test
	// you should make sure that these two aren't commented
	con.CreateMokData()
	startServer(con)
}
