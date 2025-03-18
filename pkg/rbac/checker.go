// Package rbac provides role-based access control functionality
package rbac

import (
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// PermissionChecker defines the interface for checking permissions.
// It provides methods to check different levels of access control:
// - Table level: Controls access to entire tables
// - Column level: Controls access to specific columns
// - Row level: Controls access to specific rows based on conditions
// - Query level: Combines multiple permission checks for query execution
type PermissionChecker interface {
	// Table-level permissions
	// HasTablePermission checks if a user has permission for a table
	HasTablePermission(username string, tableName string, permission permissions.PermissionType) (bool, error)

	// Column-level permissions
	// HasColumnPermission checks if a user has permission for a column
	HasColumnPermission(username string, tableName, columnName string, permission permissions.PermissionType) (bool, error)

	// Row-level permissions
	// GetRowPermissions gets the row-level permissions for a user.
	// Returns a list of RowPermissionRule that define what rows the user can access.
	GetRowPermissions(username string, tableName string, permission permissions.PermissionType) ([]permissions.RowPermissionRule, error)

	// Query-level permissions
	// CheckQueryPermissions performs a comprehensive check combining table, column, and row permissions
	// to determine if a user can execute a specific query.
	CheckQueryPermissions(username string, tableName string, permission permissions.PermissionType) (bool, error)
}
