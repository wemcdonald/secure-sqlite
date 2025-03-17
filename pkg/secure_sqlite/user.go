package secure_sqlite

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// CreateUser creates a new user in the database
func (s *SecureDB) CreateUser(username, token string) error {
	if username == "" || token == "" {
		return &DBError{
			Code:    "INVALID_INPUT",
			Message: "username and token are required",
		}
	}

	// Hash the token
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Insert the user
	_, err := s.db.Exec(`
		INSERT INTO auth_users (username, token_hash, created_at)
		VALUES (?, ?, ?)
	`, username, tokenHash, time.Now())
	if err != nil {
		return &DBError{
			Code:    "USER_CREATE_FAILED",
			Message: "failed to create user",
			Err:     err,
		}
	}

	return nil
}

// Authenticate verifies user credentials
func (s *SecureDB) Authenticate(username, token string) (bool, error) {
	if username == "" || token == "" {
		return false, &DBError{
			Code:    "INVALID_INPUT",
			Message: "username and token are required",
		}
	}

	// Hash the provided token
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Check if user exists and token matches
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM auth_users
		WHERE username = ? AND token_hash = ?
	`, username, tokenHash).Scan(&count)
	if err != nil {
		return false, &DBError{
			Code:    "AUTH_FAILED",
			Message: "authentication failed",
			Err:     err,
		}
	}

	return count > 0, nil
}

// GetUser retrieves a user by username
func (s *SecureDB) GetUser(username string) (*User, error) {
	var user User
	err := s.db.QueryRow(`
		SELECT id, username, token_hash, created_at
		FROM auth_users
		WHERE username = ?
	`, username).Scan(&user.ID, &user.Username, &user.TokenHash, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &DBError{
				Code:    "USER_NOT_FOUND",
				Message: "user not found",
			}
		}
		return nil, &DBError{
			Code:    "USER_GET_FAILED",
			Message: "failed to get user",
			Err:     err,
		}
	}
	return &user, nil
}

// UpdateUserToken updates a user's token
func (s *SecureDB) UpdateUserToken(username, newToken string) error {
	if username == "" || newToken == "" {
		return &DBError{
			Code:    "INVALID_INPUT",
			Message: "username and new token are required",
		}
	}

	// Hash the new token
	hash := sha256.Sum256([]byte(newToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Update the user's token
	result, err := s.db.Exec(`
		UPDATE auth_users
		SET token_hash = ?
		WHERE username = ?
	`, tokenHash, username)
	if err != nil {
		return &DBError{
			Code:    "TOKEN_UPDATE_FAILED",
			Message: "failed to update token",
			Err:     err,
		}
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return &DBError{
			Code:    "TOKEN_UPDATE_FAILED",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	if rows == 0 {
		return &DBError{
			Code:    "USER_NOT_FOUND",
			Message: "user not found",
		}
	}

	return nil
}

// DeleteUser removes a user from the database
func (s *SecureDB) DeleteUser(username string) error {
	result, err := s.db.Exec(`
		DELETE FROM auth_users
		WHERE username = ?
	`, username)
	if err != nil {
		return &DBError{
			Code:    "USER_DELETE_FAILED",
			Message: "failed to delete user",
			Err:     err,
		}
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return &DBError{
			Code:    "USER_DELETE_FAILED",
			Message: "failed to get rows affected",
			Err:     err,
		}
	}

	if rows == 0 {
		return &DBError{
			Code:    "USER_NOT_FOUND",
			Message: "user not found",
		}
	}

	return nil
}
