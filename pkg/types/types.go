package types

import (
	"database/sql"

	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// AuthProvider defines the interface for authentication and authorization
type AuthProvider interface {
	// Authenticate verifies a user's credentials
	Authenticate(username, token string) (bool, error)

	// GetUserPermissions returns the permissions for a user
	GetUserPermissions(username string) ([]permissions.Permission, error)

	// UpdateUserPermissions updates the permissions for a user
	UpdateUserPermissions(username string, permissions []permissions.Permission) error

	// Query executes a SELECT query
	Query(query string, args ...interface{}) (*sql.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(query string, args ...interface{}) *sql.Row

	// GetUserID returns the ID for a given username
	GetUserID(username string) (int64, error)

	// CreateUser creates a new user
	CreateUser(username, token string) error
}

// SecureDB defines the interface for secure database operations
type SecureDB interface {
	// Query executes a SELECT query with RBAC checks
	Query(username, token, query string, args ...interface{}) (*sql.Rows, error)

	// Exec executes a non-SELECT query with RBAC checks
	Exec(username, token, query string, args ...interface{}) (sql.Result, error)

	// Close closes the database connection
	Close() error

	// AuthProvider returns the authentication provider used by the database
	AuthProvider() AuthProvider

	CreateRole(name string) (int64, error)
	RoleExists(name string) (bool, error)
	AssignRoleToUser(username, roleName string) error
	UserHasRole(username, roleName string) (bool, error)
	RemoveRoleFromUser(username, roleName string) error
	DeleteRole(name string) error
	CreatePermission(name string) (int64, error)
	PermissionExists(name string) (bool, error)
	AssignPermissionToRole(roleName, permissionName string) error
	RoleHasPermission(roleName, permissionName string) (bool, error)
	RemovePermissionFromRole(roleName, permissionName string) error
	CreateUser(username, token string) error
	GrantTablePermission(roleID int64, tableName string, permissionType permissions.PermissionType) error
	GrantColumnPermission(roleID int64, tableName, columnName string, permissionType permissions.PermissionType) error
	GrantRowPermission(roleID int64, tableName, condition string, permissionType permissions.PermissionType) error
	DB() *sql.DB
}
