package auth

import (
	"net"
	"time"
)

type Question struct {
	AppName   string
	RequestIP net.IP
	Expires   time.Time
}

func NewQuestion() *Question {
	return nil
}

// check question is expired
func (q *Question) IsExpired() bool {
	return q.Expires.Before(time.Now())
}
