package secure_sqlite

import (
	"fmt"

	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// CreateRole creates a new role
func (db *SecureSQLite) CreateRole(name string) (int64, error) {
	return db.RBACManager.CreateRole(name)
}

// RoleExists checks if a role exists
func (db *SecureSQLite) RoleExists(name string) (bool, error) {
	return db.RBACManager.RoleExists(name)
}

// AssignRoleToUser assigns a role to a user
func (db *SecureSQLite) AssignRoleToUser(username, roleName string) error {
	return db.RBACManager.AssignRoleToUser(username, roleName)
}

// UserHasRole checks if a user has a role
func (db *SecureSQLite) UserHasRole(username, roleName string) (bool, error) {
	return db.RBACManager.UserHasRole(username, roleName)
}

// RemoveRoleFromUser removes a role from a user
func (db *SecureSQLite) RemoveRoleFromUser(username, roleName string) error {
	return db.RBACManager.RemoveRoleFromUser(username, roleName)
}

// DeleteRole deletes a role
func (db *SecureSQLite) DeleteRole(name string) error {
	return db.RBACManager.DeleteRole(name)
}

// CreatePermission creates a new permission
func (db *SecureSQLite) CreatePermission(name string) (int64, error) {
	return db.RBACManager.CreatePermission(name)
}

// PermissionExists checks if a permission exists
func (db *SecureSQLite) PermissionExists(name string) (bool, error) {
	return db.RBACManager.PermissionExists(name)
}

// AssignPermissionToRole assigns a permission to a role
func (db *SecureSQLite) AssignPermissionToRole(roleName, permissionName string) error {
	return db.RBACManager.AssignPermissionToRole(roleName, permissionName)
}

// RoleHasPermission checks if a role has a permission
func (db *SecureSQLite) RoleHasPermission(roleName, permissionName string) (bool, error) {
	return db.RBACManager.RoleHasPermission(roleName, permissionName)
}

// RemovePermissionFromRole removes a permission from a role
func (db *SecureSQLite) RemovePermissionFromRole(roleName, permissionName string) error {
	return db.RBACManager.RemovePermissionFromRole(roleName, permissionName)
}

// GrantTablePermission grants a table-level permission to a role
func (db *SecureSQLite) GrantTablePermission(roleID int64, tableName string, permissionType permissions.PermissionType) error {
	// Get role name from role ID
	roleName, err := db.authProvider.GetRoleName(roleID)
	if err != nil {
		return fmt.Errorf("failed to get role name: %v", err)
	}

	// Get all users with this role from auth provider
	users, err := db.authProvider.GetUsersWithRole(roleName)
	if err != nil {
		return fmt.Errorf("failed to get users with role: %v", err)
	}

	// Grant permission to each user
	for _, username := range users {
		if err := db.RBACManager.GrantTablePermission(username, tableName, permissionType); err != nil {
			return fmt.Errorf("failed to grant permission to user %s: %v", username, err)
		}
	}

	return nil
}

// GrantColumnPermission grants a column-level permission to a role
func (db *SecureSQLite) GrantColumnPermission(roleID int64, tableName, columnName string, permissionType permissions.PermissionType) error {
	// Get role name from role ID
	roleName, err := db.authProvider.GetRoleName(roleID)
	if err != nil {
		return fmt.Errorf("failed to get role name: %v", err)
	}

	// Get all users with this role from auth provider
	users, err := db.authProvider.GetUsersWithRole(roleName)
	if err != nil {
		return fmt.Errorf("failed to get users with role: %v", err)
	}

	// Grant permission to each user
	for _, username := range users {
		if err := db.RBACManager.GrantColumnPermission(username, tableName, columnName, permissionType); err != nil {
			return fmt.Errorf("failed to grant permission to user %s: %v", username, err)
		}
	}

	return nil
}

// GrantRowPermission grants a row-level permission to a role
func (db *SecureSQLite) GrantRowPermission(roleID int64, tableName, condition string, permissionType permissions.PermissionType) error {
	// Get role name from role ID
	roleName, err := db.authProvider.GetRoleName(roleID)
	if err != nil {
		return fmt.Errorf("failed to get role name: %v", err)
	}

	// Get all users with this role from auth provider
	users, err := db.authProvider.GetUsersWithRole(roleName)
	if err != nil {
		return fmt.Errorf("failed to get users with role: %v", err)
	}

	// Grant permission to each user
	for _, username := range users {
		if err := db.RBACManager.GrantRowPermission(username, tableName, condition, permissionType); err != nil {
			return fmt.Errorf("failed to grant permission to user %s: %v", username, err)
		}
	}

	return nil
}
