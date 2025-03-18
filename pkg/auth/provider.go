package auth

import (
	"database/sql"

	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// Provider defines the interface for authentication
type Provider interface {
	// Authenticate verifies if the given username and token are valid
	Authenticate(username, token string) (bool, error)

	// GetUserPermissions returns the list of permissions for a user
	GetUserPermissions(username string) ([]permissions.Permission, error)

	// Query executes a SELECT query
	Query(query string, args ...interface{}) (*sql.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(query string, args ...interface{}) *sql.Row

	// UpdateUserPermissions updates the permissions for a user
	UpdateUserPermissions(username string, permissions []permissions.Permission) error

	// AddUser adds a user with the given credentials
	AddUser(username, token string)

	// AddPermission adds a permission for a user
	AddPermission(username string, permission permissions.Permission)

	// GetUserID returns the numeric ID for a user
	GetUserID(username string) (int64, error)

	// GetUsersWithRole returns a list of usernames that have the given role
	GetUsersWithRole(roleName string) ([]string, error)

	// GetRoleName returns the name of a role given its ID
	GetRoleName(roleID int64) (string, error)

	// GetRoleID returns the ID of a role given its name
	GetRoleID(roleName string) (int64, error)

	// AddRole adds a role and returns its ID
	AddRole(roleName string) (int64, error)

	// DeleteRole deletes a role
	DeleteRole(roleID int64) error

	// StoreSession stores a session for a user
	StoreSession(sessionID string, userID int64) error

	// ValidateSession checks if a session is valid
	ValidateSession(sessionID string) (bool, error)

	// TerminateSession terminates a session
	TerminateSession(sessionID string) error
}
