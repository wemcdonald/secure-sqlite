package secure_sqlite

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const (
	sessionIDLength = 32
	sessionDuration = 24 * time.Hour
)

// CreateSession creates a new session for a user
func (s *SecureDB) CreateSession(username, token string) (*Session, error) {
	// First authenticate the user
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

	// Generate a random session ID
	sessionID := make([]byte, sessionIDLength)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, &DBError{
			Code:    "SESSION_CREATE_FAILED",
			Message: "failed to generate session ID",
			Err:     err,
		}
	}

	// Create the session
	now := time.Now()
	expiresAt := now.Add(sessionDuration)

	_, err = s.db.Exec(`
		INSERT INTO auth_sessions (id, username, created_at, expires_at)
		VALUES (?, ?, ?, ?)
	`, hex.EncodeToString(sessionID), username, now, expiresAt)
	if err != nil {
		return nil, &DBError{
			Code:    "SESSION_CREATE_FAILED",
			Message: "failed to create session",
			Err:     err,
		}
	}

	return &Session{
		ID:        hex.EncodeToString(sessionID),
		Username:  username,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateSession checks if a session is valid
func (s *SecureDB) ValidateSession(sessionID string) (bool, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM auth_sessions
		WHERE id = ? AND expires_at > ?
	`, sessionID, time.Now()).Scan(&count)
	if err != nil {
		return false, &DBError{
			Code:    "SESSION_VALIDATE_FAILED",
			Message: "failed to validate session",
			Err:     err,
		}
	}

	return count > 0, nil
}

// GetSession retrieves a session by ID
func (s *SecureDB) GetSession(sessionID string) (*Session, error) {
	var session Session
	err := s.db.QueryRow(`
		SELECT id, username, created_at, expires_at
		FROM auth_sessions
		WHERE id = ? AND expires_at > ?
	`, sessionID, time.Now()).Scan(&session.ID, &session.Username, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &DBError{
				Code:    "SESSION_NOT_FOUND",
				Message: "session not found or expired",
			}
		}
		return nil, &DBError{
			Code:    "SESSION_GET_FAILED",
			Message: "failed to get session",
			Err:     err,
		}
	}
	return &session, nil
}

// TerminateSession ends a session
func (s *SecureDB) TerminateSession(sessionID string) error {
	result, err := s.db.Exec(`
		DELETE FROM auth_sessions
		WHERE id = ?
	`, sessionID)
	if err != nil {
		return &DBError{
			Code:    "SESSION_TERMINATE_FAILED",
			Message: "failed to terminate session",
			Err:     err,
		}
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return &DBError{
			Code:    "SESSION_TERMINATE_FAILED",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	if rows == 0 {
		return &DBError{
			Code:    "SESSION_NOT_FOUND",
			Message: "session not found",
		}
	}

	return nil
}

// CleanupExpiredSessions removes all expired sessions
func (s *SecureDB) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`
		DELETE FROM auth_sessions
		WHERE expires_at <= ?
	`, time.Now())
	if err != nil {
		return &DBError{
			Code:    "SESSION_CLEANUP_FAILED",
			Message: "failed to cleanup expired sessions",
			Err:     err,
		}
	}
	return nil
}
