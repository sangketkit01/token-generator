package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sangketkit01/token-generator/token"
)

type Server struct {
	router *gin.Engine
}

func NewServer() (*Server, error){
	router := gin.Default()
	server := &Server{
		router: router,
	}
	
	router.GET("/test", server.TestHandleFunc)

	err := router.Run(":8080")
	if err != nil{
		return nil, err
	}

	return server,nil
}

func (server *Server) TestHandleFunc(c *gin.Context){
	_, ok := c.MustGet(authorizationPayloadKey).(*token.Payload)
	if !ok{
		c.JSON(http.StatusUnauthorized, gin.H{"eror" : "invalid token."})
		return
	}

	c.JSON(http.StatusOK, "Hello world")
}
