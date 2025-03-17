package secure_sqlite

import (
	"database/sql"
	"time"

	"github.com/wemcdonald/secure_sqlite/internal/auth"
)

// Session represents a user's database session
type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// User represents a database user
type User struct {
	ID        int64
	Username  string
	TokenHash string
	CreatedAt time.Time
}

// Config holds the configuration for the secure database
type Config struct {
	DBPath       string
	AuthProvider auth.Provider
}

// SecureDB wraps the SQLite database with authentication and authorization
type SecureDB struct {
	db           *sql.DB
	authProvider auth.Provider
}

// DBError represents a database-specific error
type DBError struct {
	Code    string
	Message string
	Err     error
}

func (e *DBError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *DBError) Unwrap() error {
	return e.Err
}
