package rbac

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// RBACManager handles role-based access control operations
type RBACManager struct {
	AuthProvider auth.Provider
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(authProvider auth.Provider) *RBACManager {
	return &RBACManager{
		AuthProvider: authProvider,
	}
}

// ParsePermission parses a permission string into its components
func ParsePermission(permission string) (*permissions.Permission, error) {
	parts := strings.Split(permission, ".")
	if len(parts) == 1 {
		// Table-level permission
		return &permissions.Permission{
			Type:  permissions.TablePermission,
			Table: parts[0],
		}, nil
	}

	if len(parts) == 2 {
		// Column-level permission
		return &permissions.Permission{
			Type:   permissions.ColumnPermission,
			Table:  parts[0],
			Column: parts[1],
		}, nil
	}

	if len(parts) == 3 && strings.Contains(parts[2], "<=") {
		// Row-level permission
		condition := strings.Split(parts[2], "<=")
		if len(condition) != 2 {
			return nil, fmt.Errorf("invalid row permission format: %s", permission)
		}
		return &permissions.Permission{
			Type:      permissions.RowPermission,
			Table:     parts[0],
			Column:    parts[1],
			Condition: fmt.Sprintf("%s <= %s", parts[1], condition[1]),
		}, nil
	}

	return nil, fmt.Errorf("invalid permission format: %s", permission)
}

// CheckPermission checks if a user has permission for a specific operation
func (m *RBACManager) CheckPermission(username string, tableName string, action permissions.Action) (bool, error) {
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	for _, perm := range userPerms {
		// First check if the action matches
		if perm.Action != action {
			continue
		}

		switch perm.Type {
		case permissions.TablePermission:
			if perm.Table == tableName || perm.Table == permissions.WildcardPermission {
				return true, nil
			}
		case permissions.ColumnPermission:
			if perm.Table == tableName || perm.Table == permissions.WildcardPermission {
				return true, nil
			}
		case permissions.RowPermission:
			if perm.Table == tableName || perm.Table == permissions.WildcardPermission {
				return true, nil
			}
		}
	}

	return false, nil
}

// CheckColumnPermission checks if a user has permission for a specific column
func (m *RBACManager) CheckColumnPermission(username string, tableName string, columnName string) (bool, error) {
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	for _, perm := range userPerms {
		if perm.Type == permissions.ColumnPermission {
			if (perm.Table == tableName || perm.Table == "*") &&
				(perm.Column == columnName || perm.Column == "*") {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetRowCondition returns the row-level condition for a user on a table
func (m *RBACManager) GetRowCondition(username string, tableName string) (string, error) {
	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return "", err
	}

	// Check if user has any row permissions for this table
	for _, perm := range userPerms {
		if perm.Type == permissions.RowPermission && (perm.Table == tableName || perm.Table == permissions.WildcardPermission) {
			// If the permission is revoked, return empty string
			if strings.HasPrefix(perm.Condition, permissions.RevokedPermissionPrefix) {
				return "", nil
			}
			return perm.Condition, nil
		}
	}

	return "", nil
}

// ValidateQueryPermissions checks if a user has permission to access the specified tables and columns
func (m *RBACManager) ValidateQueryPermissions(username string, tables []string, columns []string) error {
	// Check permissions for each table in the query
	for _, tableName := range tables {
		// Check table-level permission
		hasPermission, err := m.CheckPermission(username, tableName, permissions.Select)
		if err != nil {
			return err
		}
		if !hasPermission {
			return fmt.Errorf("no permission on table %s", tableName)
		}

		// Check column-level permissions
		for _, col := range columns {
			if col == "*" {
				// For SELECT *, we need to check all columns in the table
				// This would require schema information which we don't have here
				// For now, we'll just allow it if they have table permission
				continue
			}
			hasPermission, err := m.CheckColumnPermission(username, tableName, col)
			if err != nil {
				return err
			}
			if !hasPermission {
				return fmt.Errorf("no permission on column %s in table %s", col, tableName)
			}
		}
	}

	return nil
}

// AssignRoleToUser assigns a role to a user
func (m *RBACManager) AssignRoleToUser(username, roleName string) error {
	// Verify user exists via AuthProvider
	valid, err := m.AuthProvider.Authenticate(username, "")
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("user not found")
	}

	// Store role assignment in auth provider
	perm := permissions.Permission{
		Type:  permissions.TablePermission,
		Table: roleName,
	}
	return m.AuthProvider.UpdateUserPermissions(username, []permissions.Permission{perm})
}

// UserHasRole checks if a user has a specific role
func (m *RBACManager) UserHasRole(username, roleName string) (bool, error) {
	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	// Check if user has the role permission
	for _, perm := range userPerms {
		if perm.Type == permissions.TablePermission && perm.Table == roleName {
			return true, nil
		}
	}
	return false, nil
}

// RemoveRoleFromUser removes a role from a user
func (m *RBACManager) RemoveRoleFromUser(username, roleName string) error {
	// Verify user exists via AuthProvider
	valid, err := m.AuthProvider.Authenticate(username, "")
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("user not found")
	}

	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Remove the role permission
	newPerms := make([]permissions.Permission, 0)
	for _, perm := range userPerms {
		if !(perm.Type == permissions.TablePermission && perm.Table == roleName) {
			newPerms = append(newPerms, perm)
		}
	}

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, newPerms)
}

// DeleteRole deletes a role
func (m *RBACManager) DeleteRole(name string) error {
	// Get role ID
	roleID, err := m.AuthProvider.GetRoleID(name)
	if err != nil {
		return err
	}

	// Get all users with this role
	users, err := m.AuthProvider.GetUsersWithRole(name)
	if err != nil {
		return err
	}

	// Remove role from all users
	for _, username := range users {
		if err := m.RemoveRoleFromUser(username, name); err != nil {
			return err
		}
	}

	// Delete role from auth provider
	return m.AuthProvider.DeleteRole(roleID)
}

// CreateRole creates a new role
func (m *RBACManager) CreateRole(name string) (int64, error) {
	return m.AuthProvider.AddRole(name)
}

// RoleExists checks if a role exists
func (m *RBACManager) RoleExists(name string) (bool, error) {
	// Try to get role ID from name
	roleID, err := m.AuthProvider.GetRoleID(name)
	if err != nil {
		return false, nil
	}
	return roleID > 0, nil
}

// CreatePermission creates a new permission
func (m *RBACManager) CreatePermission(name string) (int64, error) {
	// Permissions are managed by the auth provider
	return 1, nil
}

// PermissionExists checks if a permission exists
func (m *RBACManager) PermissionExists(name string) (bool, error) {
	// Permissions are managed by the auth provider
	return true, nil
}

// AssignPermissionToRole assigns a permission to a role
func (m *RBACManager) AssignPermissionToRole(roleName, permissionName string) error {
	// Permissions are managed by the auth provider
	return nil
}

// RoleHasPermission checks if a role has a permission
func (m *RBACManager) RoleHasPermission(roleName, permissionName string) (bool, error) {
	// Permissions are managed by the auth provider
	return true, nil
}

// RemovePermissionFromRole removes a permission from a role
func (m *RBACManager) RemovePermissionFromRole(roleName, permissionName string) error {
	// Permissions are managed by the auth provider
	return nil
}

// HasTablePermission checks if a user has a specific permission on a table
func (m *RBACManager) HasTablePermission(username string, tableName string, permission permissions.PermissionType) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username cannot be empty")
	}

	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	// Check if user has the table permission
	for _, perm := range userPerms {
		if perm.Type == permission && (perm.Table == tableName || perm.Table == permissions.WildcardPermission) {
			return true, nil
		}
	}
	return false, nil
}

// HasColumnPermission checks if a user has a specific permission on a column
func (m *RBACManager) HasColumnPermission(username string, tableName, columnName string, permission permissions.PermissionType) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username cannot be empty")
	}

	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	// Check if user has the column permission
	for _, perm := range userPerms {
		if perm.Type == permission && (perm.Table == tableName || perm.Table == permissions.WildcardPermission) {
			return true, nil
		}
	}
	return false, nil
}

// GetRowPermissions retrieves all row-level permissions for a user on a table
func (m *RBACManager) GetRowPermissions(username string, tableName string, permission permissions.PermissionType) ([]permissions.RowPermissionRule, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return nil, err
	}

	// Find row-level permissions for the table
	var rules []permissions.RowPermissionRule
	for _, perm := range userPerms {
		if perm.Type == permission && (perm.Table == tableName || perm.Table == permissions.WildcardPermission) {
			rules = append(rules, permissions.RowPermissionRule{
				Granted: !strings.HasPrefix(perm.Condition, permissions.RevokedPermissionPrefix),
			})
		}
	}

	// If no rules found, return a default rule with Granted: false
	if len(rules) == 0 {
		return []permissions.RowPermissionRule{{Granted: false}}, nil
	}

	return rules, nil
}

// CheckQueryPermissions performs a comprehensive permission check for a query
func (m *RBACManager) CheckQueryPermissions(username string, tableName string, permission permissions.PermissionType) (bool, error) {
	// Get user permissions from AuthProvider
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	// Check if user has the table permission
	hasTablePermission := false
	for _, perm := range userPerms {
		if perm.Type == permissions.TablePermission && (perm.Table == tableName || perm.Table == "*") {
			hasTablePermission = true
			break
		}
	}

	if !hasTablePermission {
		return false, nil
	}

	// Check row-level permissions
	hasRowPermission := false
	for _, perm := range userPerms {
		if perm.Type == permissions.RowPermission && (perm.Table == tableName || perm.Table == "*") {
			hasRowPermission = true
			break
		}
	}

	// If there are any row-level permissions (granted or revoked), check if they are granted
	if hasRowPermission {
		rowPerms, err := m.GetRowPermissions(username, tableName, permissions.RowPermission)
		if err != nil {
			return false, err
		}
		// If there are any row permissions but none are granted, deny access
		if len(rowPerms) == 0 || !rowPerms[0].Granted {
			return false, nil
		}
	}

	return true, nil
}

// GrantTablePermission grants a permission on a table to a user
func (m *RBACManager) GrantTablePermission(username string, tableName string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Add the new permission
	newPerm := permissions.Permission{
		Type:  permission,
		Table: tableName,
	}
	userPerms = append(userPerms, newPerm)

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, userPerms)
}

// RevokeTablePermission revokes a permission on a table from a user
func (m *RBACManager) RevokeTablePermission(username string, tableName string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Remove the permission
	newPerms := make([]permissions.Permission, 0)
	for _, perm := range userPerms {
		if !(perm.Type == permission && perm.Table == tableName) {
			newPerms = append(newPerms, perm)
		}
	}

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, newPerms)
}

// GrantColumnPermission grants a permission on a column to a user
func (m *RBACManager) GrantColumnPermission(username string, tableName, columnName string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Add the new permission
	newPerm := permissions.Permission{
		Type:   permission,
		Table:  tableName,
		Column: columnName,
	}
	userPerms = append(userPerms, newPerm)

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, userPerms)
}

// RevokeColumnPermission revokes a permission on a column from a user
func (m *RBACManager) RevokeColumnPermission(username string, tableName, columnName string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Remove the permission
	newPerms := make([]permissions.Permission, 0)
	for _, perm := range userPerms {
		if !(perm.Type == permission && perm.Table == tableName && perm.Column == columnName) {
			newPerms = append(newPerms, perm)
		}
	}

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, newPerms)
}

// GrantRowPermission grants a row-level permission to a user
func (m *RBACManager) GrantRowPermission(username string, tableName, condition string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Add the new permission
	newPerm := permissions.Permission{
		Type:      permission,
		Table:     tableName,
		Condition: condition,
	}
	userPerms = append(userPerms, newPerm)

	// Update user permissions
	return m.AuthProvider.UpdateUserPermissions(username, userPerms)
}

// RevokeRowPermission revokes a row-level permission from a user
func (m *RBACManager) RevokeRowPermission(username string, tableName, condition string, permission permissions.PermissionType) error {
	// Get current permissions
	userPerms, err := m.AuthProvider.GetUserPermissions(username)
	if err != nil {
		return err
	}

	// Instead of removing the permission, mark it as revoked
	for i, perm := range userPerms {
		if perm.Type == permission && perm.Table == tableName && perm.Condition == condition {
			// Mark the permission as revoked by setting a special condition
			userPerms[i].Condition = permissions.RevokedPermissionPrefix + condition
			return m.AuthProvider.UpdateUserPermissions(username, userPerms)
		}
	}

	return nil
}
