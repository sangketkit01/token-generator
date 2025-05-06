package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sangketkit01/token-generator/token"
)

const (
	authorizationHeaderKey    = "authorization"
	authorizationHeaderBearer = "bearer"
	authorizationPayloadKey   = "authorization_paylod"
)

func authMiddleware(tokenMaker token.Maker) gin.HandlerFunc{
	return func(c *gin.Context){
		authorizationHeader := c.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			err := errors.New("authorization header is not provided")
			c.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		fields := strings.Fields(authorizationHeader)
		// fields = (authorizationHeader, authorizationHeaderType, ...)
		if len(fields) < 2{
			err := errors.New("invalid authorization header form")
			c.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		authorizationHeaderType := strings.ToLower(fields[0])
		if authorizationHeaderType != authorizationHeaderBearer{
			err := fmt.Errorf("unssported authorization type %s", authorizationHeaderType)
			c.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil{
			c.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		c.Set(authorizationPayloadKey, payload)
		c.Next()
	}
}