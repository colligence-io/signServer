package auth

import "time"

type Session struct {
	JWS     string
	AppName string
	// key = symbol:address
	Quizzes map[string]Quiz
	Expires time.Time
}

type Quiz struct {
	Question string
	Answer   string
	KeyID    string
}

// check session is expired
func (s *Session) IsExpired() bool {
	return s.Expires.Before(time.Now())
}
