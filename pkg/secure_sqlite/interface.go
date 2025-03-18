package secure_sqlite

import (
	"database/sql"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// SecureDB defines the interface for secure database operations
type SecureDB interface {
	// Core operations
	Open(dataSourceName string, authProvider auth.Provider, username, token string) (*SecureSQLite, error)
	Close() error
	AuthProvider() auth.Provider
	DB() *sql.DB
	Ping() error

	// User management
	CreateUser(username, token string) error

	// RBAC operations
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
	GrantTablePermission(roleID int64, tableName string, permissionType permissions.PermissionType) error
	GrantColumnPermission(roleID int64, tableName, columnName string, permissionType permissions.PermissionType) error
	GrantRowPermission(roleID int64, tableName, condition string, permissionType permissions.PermissionType) error

	// Query operations
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
	Prepare(query string) (*sql.Stmt, error)
	Begin() (*sql.Tx, error)
}
