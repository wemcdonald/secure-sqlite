package rbac

import (
	"testing"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// testUser represents test user credentials
const (
	testUsername = "test_user"
	testToken    = "test_token"
	testTable    = "test_table"
	testColumn   = "test_column"
)

// testSetup encapsulates common test setup functionality
type testSetup struct {
	auth auth.Provider
	rbac *RBACManager
	t    *testing.T
}

// newTestSetup creates a new test setup with initialized dependencies
func newTestSetup(t *testing.T) *testSetup {
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser(testUsername, testToken)

	return &testSetup{
		auth: mockAuth,
		rbac: NewRBACManager(mockAuth),
		t:    t,
	}
}

// assertNoError fails the test if err is not nil
func (ts *testSetup) assertNoError(err error, msg string) {
	if err != nil {
		ts.t.Fatalf("%s: %v", msg, err)
	}
}

// assertPermission checks if the permission matches expected value
func (ts *testSetup) assertPermission(got bool, want bool, msg string) {
	if got != want {
		ts.t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

func TestTablePermissions(t *testing.T) {
	ts := newTestSetup(t)

	// Test initial state - no permissions
	hasPermission, err := ts.rbac.HasTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check initial table permission")
	ts.assertPermission(hasPermission, false, "Expected no initial table permission")

	// Test granting table permission
	err = ts.rbac.GrantTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to grant table permission")

	// Test checking table permission
	hasPermission, err = ts.rbac.HasTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check table permission")
	ts.assertPermission(hasPermission, true, "Expected table permission to be granted")

	// Test revoking table permission
	err = ts.rbac.RevokeTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to revoke table permission")

	// Verify permission is revoked
	hasPermission, err = ts.rbac.HasTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check table permission")
	ts.assertPermission(hasPermission, false, "Expected table permission to be revoked")
}

func TestColumnPermissions(t *testing.T) {
	ts := newTestSetup(t)

	// Test initial state - no permissions
	hasPermission, err := ts.rbac.HasColumnPermission(testUsername, testTable, testColumn, permissions.ColumnPermission)
	ts.assertNoError(err, "Failed to check initial column permission")
	ts.assertPermission(hasPermission, false, "Expected no initial column permission")

	// Test granting column permission
	err = ts.rbac.GrantColumnPermission(testUsername, testTable, testColumn, permissions.ColumnPermission)
	ts.assertNoError(err, "Failed to grant column permission")

	// Test checking column permission
	hasPermission, err = ts.rbac.HasColumnPermission(testUsername, testTable, testColumn, permissions.ColumnPermission)
	ts.assertNoError(err, "Failed to check column permission")
	ts.assertPermission(hasPermission, true, "Expected column permission to be granted")

	// Test revoking column permission
	err = ts.rbac.RevokeColumnPermission(testUsername, testTable, testColumn, permissions.ColumnPermission)
	ts.assertNoError(err, "Failed to revoke column permission")

	// Test permission is revoked
	hasPermission, err = ts.rbac.HasColumnPermission(testUsername, testTable, testColumn, permissions.ColumnPermission)
	ts.assertNoError(err, "Failed to check column permission")
	ts.assertPermission(hasPermission, false, "Expected column permission to be revoked")
}

func TestRowPermissions(t *testing.T) {
	ts := newTestSetup(t)
	condition := "user_id = 1"

	// Test initial state - no permissions
	rowPerms, err := ts.rbac.GetRowPermissions(testUsername, testTable, permissions.RowPermission)
	ts.assertNoError(err, "Failed to get initial row permissions")
	if len(rowPerms) != 1 {
		t.Errorf("Expected 1 row permission, got %d", len(rowPerms))
	}
	if rowPerms[0].Granted {
		t.Error("Expected initial row permission to be not granted")
	}

	// Test granting row permission
	err = ts.rbac.GrantRowPermission(testUsername, testTable, condition, permissions.RowPermission)
	ts.assertNoError(err, "Failed to grant row permission")

	// Test checking row permission
	rowPerms, err = ts.rbac.GetRowPermissions(testUsername, testTable, permissions.RowPermission)
	ts.assertNoError(err, "Failed to get row permissions")
	if len(rowPerms) != 1 {
		t.Errorf("Expected 1 row permission, got %d", len(rowPerms))
	}
	if !rowPerms[0].Granted {
		t.Error("Expected row permission to be granted")
	}

	// Test revoking row permission
	err = ts.rbac.RevokeRowPermission(testUsername, testTable, condition, permissions.RowPermission)
	ts.assertNoError(err, "Failed to revoke row permission")

	// Test permission is revoked
	rowPerms, err = ts.rbac.GetRowPermissions(testUsername, testTable, permissions.RowPermission)
	ts.assertNoError(err, "Failed to get row permissions")
	if len(rowPerms) != 1 {
		t.Errorf("Expected 1 row permission, got %d", len(rowPerms))
	}
	if rowPerms[0].Granted {
		t.Error("Expected row permission to be revoked")
	}
}

func TestQueryPermissions(t *testing.T) {
	ts := newTestSetup(t)

	// Test initial state - no permissions
	hasPermission, err := ts.rbac.CheckQueryPermissions(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check initial query permission")
	ts.assertPermission(hasPermission, false, "Expected no initial query permission")

	// Grant table permission
	err = ts.rbac.GrantTablePermission(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to grant table permission")

	// Test query permission with table permission
	hasPermission, err = ts.rbac.CheckQueryPermissions(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check query permission")
	ts.assertPermission(hasPermission, true, "Expected query permission to be granted")

	// Add row-level permission
	condition := "user_id = 1"
	err = ts.rbac.GrantRowPermission(testUsername, testTable, condition, permissions.RowPermission)
	ts.assertNoError(err, "Failed to grant row permission")

	// Test query permission with both table and row permissions
	hasPermission, err = ts.rbac.CheckQueryPermissions(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check query permission")
	ts.assertPermission(hasPermission, true, "Expected query permission to be granted")

	// Revoke row permission
	err = ts.rbac.RevokeRowPermission(testUsername, testTable, condition, permissions.RowPermission)
	ts.assertNoError(err, "Failed to revoke row permission")

	// Test query permission with revoked row permission
	hasPermission, err = ts.rbac.CheckQueryPermissions(testUsername, testTable, permissions.TablePermission)
	ts.assertNoError(err, "Failed to check query permission")
	ts.assertPermission(hasPermission, false, "Expected query permission to be denied due to revoked row permission")
}

func TestRBACManager_GrantTablePermission(t *testing.T) {
	// Create a mock auth provider
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser("test_user", "test_token")
	rbacManager := NewRBACManager(mockAuth)

	// Test granting table permission
	err := rbacManager.GrantTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to grant table permission: %v", err)
	}

	// Test checking table permission
	hasPermission, err := rbacManager.HasTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to check table permission: %v", err)
	}
	if !hasPermission {
		t.Error("Expected table permission to be granted")
	}
}

func TestRBACManager_TablePermissions(t *testing.T) {
	// Create a mock auth provider
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser("test_user", "test_token")
	rbacManager := NewRBACManager(mockAuth)

	// Test granting table permission
	err := rbacManager.GrantTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to grant table permission: %v", err)
	}

	// Test checking table permission
	hasPermission, err := rbacManager.HasTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to check table permission: %v", err)
	}
	if !hasPermission {
		t.Error("Expected table permission to be granted")
	}

	// Test revoking table permission
	err = rbacManager.RevokeTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to revoke table permission: %v", err)
	}

	// Test permission is revoked
	hasPermission, err = rbacManager.HasTablePermission("test_user", "test_table", permissions.TablePermission)
	if err != nil {
		t.Errorf("Failed to check table permission: %v", err)
	}
	if hasPermission {
		t.Error("Expected table permission to be revoked")
	}
}

func TestRBACManager_ColumnPermissions(t *testing.T) {
	// Create a mock auth provider
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser("test_user", "test_token")
	rbacManager := NewRBACManager(mockAuth)

	// Test granting column permission
	err := rbacManager.GrantColumnPermission("test_user", "test_table", "test_column", permissions.ColumnPermission)
	if err != nil {
		t.Errorf("Failed to grant column permission: %v", err)
	}

	// Test checking column permission
	hasPermission, err := rbacManager.HasColumnPermission("test_user", "test_table", "test_column", permissions.ColumnPermission)
	if err != nil {
		t.Errorf("Failed to check column permission: %v", err)
	}
	if !hasPermission {
		t.Error("Expected column permission to be granted")
	}

	// Test revoking column permission
	err = rbacManager.RevokeColumnPermission("test_user", "test_table", "test_column", permissions.ColumnPermission)
	if err != nil {
		t.Errorf("Failed to revoke column permission: %v", err)
	}

	// Test permission is revoked
	hasPermission, err = rbacManager.HasColumnPermission("test_user", "test_table", "test_column", permissions.ColumnPermission)
	if err != nil {
		t.Errorf("Failed to check column permission: %v", err)
	}
	if hasPermission {
		t.Error("Expected column permission to be revoked")
	}
}

func TestRBACManager_RowPermissions(t *testing.T) {
	// Create a mock auth provider
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser("test_user", "test_token")
	rbacManager := NewRBACManager(mockAuth)

	// Test granting row permission
	condition := "user_id = 1"
	err := rbacManager.GrantRowPermission("test_user", "test_table", condition, permissions.RowPermission)
	if err != nil {
		t.Errorf("Failed to grant row permission: %v", err)
	}

	// Test checking row permission
	rowCondition, err := rbacManager.GetRowCondition("test_user", "test_table")
	if err != nil {
		t.Errorf("Failed to get row condition: %v", err)
	}
	if rowCondition == "" {
		t.Error("Expected row condition to be set")
	}

	// Test revoking row permission
	err = rbacManager.RevokeRowPermission("test_user", "test_table", condition, permissions.RowPermission)
	if err != nil {
		t.Errorf("Failed to revoke row permission: %v", err)
	}

	// Test permission is revoked
	rowCondition, err = rbacManager.GetRowCondition("test_user", "test_table")
	if err != nil {
		t.Errorf("Failed to get row condition: %v", err)
	}
	if rowCondition != "" {
		t.Error("Expected row condition to be empty")
	}
}
