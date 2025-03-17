package secure_sqlite

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// NewSecureDB creates a new secure database instance
func NewSecureDB(config Config) (*SecureDB, error) {
	if config.DBPath == "" {
		return nil, &DBError{
			Code:    "INVALID_CONFIG",
			Message: "database path is required",
		}
	}
	if config.AuthProvider == nil {
		return nil, &DBError{
			Code:    "INVALID_CONFIG",
			Message: "auth provider is required",
		}
	}

	db, err := sql.Open("sqlite3", config.DBPath)
	if err != nil {
		return nil, &DBError{
			Code:    "DB_OPEN_FAILED",
			Message: "failed to open database",
			Err:     err,
		}
	}

	// Initialize the database schema
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &SecureDB{
		db:           db,
		authProvider: config.AuthProvider,
	}, nil
}

// Close closes the database connection
func (s *SecureDB) Close() error {
	return s.db.Close()
}

// Query executes a query with authentication check
func (s *SecureDB) Query(username, token, query string, args ...interface{}) (*sql.Rows, error) {
	authenticated, err := s.Authenticate(username, token)
	if err != nil {
		return nil, err
	}
	if !authenticated {
		return nil, &DBError{
			Code:    "AUTH_FAILED",
			Message: "authentication failed",
		}
	}

	// TODO: Add permission checking based on the query
	return s.db.Query(query, args...)
}

// Exec executes a command with authentication check
func (s *SecureDB) Exec(username, token, query string, args ...interface{}) (sql.Result, error) {
	authenticated, err := s.Authenticate(username, token)
	if err != nil {
		return nil, err
	}
	if !authenticated {
		return nil, &DBError{
			Code:    "AUTH_FAILED",
			Message: "authentication failed",
		}
	}

	// TODO: Add permission checking based on the query
	return s.db.Exec(query, args...)
}

// initSchema creates the necessary database tables
func initSchema(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS auth_users (
			id INTEGER PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			token_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (username) REFERENCES auth_users(username)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_username ON auth_sessions(username)`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return &DBError{
				Code:    "SCHEMA_INIT_FAILED",
				Message: "failed to initialize database schema",
				Err:     err,
			}
		}
	}

	return nil
}

// Begin starts a new transaction
func (s *SecureDB) Begin(username, token string) (*sql.Tx, error) {
	authenticated, err := s.Authenticate(username, token)
	if err != nil {
		return nil, err
	}
	if !authenticated {
		return nil, &DBError{
			Code:    "AUTH_FAILED",
			Message: "authentication failed",
		}
	}

	return s.db.Begin()
}
