package token

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Payload struct {
	TokenID uuid.UUID `json:"token_id"`
	Username string `json:"username"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

func NewPayload(username string, duration time.Duration) (*Payload, error){
	tokenId, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &Payload{
		TokenID: tokenId,
		Username: username,
		IssuedAt: time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}, nil
}

func (payload *Payload) Valid() error{
	if time.Now().After(payload.ExpiredAt){
		return fmt.Errorf("Token has expired.")
	}

	return nil
}