package auth

import (
	"database/sql"
	"testing"

	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

func TestNewMemoryProvider(t *testing.T) {
	provider := NewMemoryProvider()
	if provider == nil {
		t.Error("NewMemoryProvider returned nil")
	}
}

func TestMemoryProvider_AddUser(t *testing.T) {
	provider := NewMemoryProvider()
	username := "testuser"
	token := "testtoken"

	provider.AddUser(username, token)

	// Test authentication with correct credentials
	authenticated, err := provider.Authenticate(username, token)
	if err != nil {
		t.Errorf("Authenticate returned unexpected error: %v", err)
	}
	if !authenticated {
		t.Error("Authentication failed with correct credentials")
	}

	// Test authentication with incorrect token
	authenticated, err = provider.Authenticate(username, "wrongtoken")
	if err != nil {
		t.Errorf("Authenticate returned unexpected error: %v", err)
	}
	if authenticated {
		t.Error("Authentication succeeded with incorrect token")
	}
}

func TestMemoryProvider_AddPermission(t *testing.T) {
	provider := NewMemoryProvider()
	username := "testuser"
	token := "testtoken"
	provider.AddUser(username, token)

	permission := permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	}

	provider.AddPermission(username, permission)

	// Test getting permissions
	perms, err := provider.GetUserPermissions(username)
	if err != nil {
		t.Errorf("GetUserPermissions returned unexpected error: %v", err)
	}
	if len(perms) != 1 {
		t.Errorf("Expected 1 permission, got %d", len(perms))
	}
	if perms[0] != permission {
		t.Error("Retrieved permission does not match added permission")
	}
}

func TestMemoryProvider_UpdateUserPermissions(t *testing.T) {
	provider := NewMemoryProvider()
	username := "testuser"
	token := "testtoken"
	provider.AddUser(username, token)

	initialPermission := permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	}
	provider.AddPermission(username, initialPermission)

	newPermissions := []permissions.Permission{
		{
			Type:  permissions.TablePermission,
			Table: "new_table",
		},
		{
			Type:  permissions.TablePermission,
			Table: "another_table",
		},
	}

	err := provider.UpdateUserPermissions(username, newPermissions)
	if err != nil {
		t.Errorf("UpdateUserPermissions returned unexpected error: %v", err)
	}

	// Verify permissions were updated
	perms, err := provider.GetUserPermissions(username)
	if err != nil {
		t.Errorf("GetUserPermissions returned unexpected error: %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(perms))
	}
	if perms[0] != newPermissions[0] || perms[1] != newPermissions[1] {
		t.Error("Retrieved permissions do not match updated permissions")
	}
}

func TestMemoryProvider_Query(t *testing.T) {
	provider := NewMemoryProvider()
	rows, err := provider.Query("SELECT * FROM test")
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
	if rows != nil {
		t.Error("Expected nil rows")
	}
}

func TestMemoryProvider_QueryRow(t *testing.T) {
	provider := NewMemoryProvider()
	row := provider.QueryRow("SELECT * FROM test")
	if row != nil {
		t.Error("Expected nil row")
	}
}

func TestMemoryProvider_ConcurrentAccess(t *testing.T) {
	provider := NewMemoryProvider()
	username := "testuser"
	token := "testtoken"
	permission := permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	}

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			provider.AddUser(username, token)
			provider.AddPermission(username, permission)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final state
	authenticated, err := provider.Authenticate(username, token)
	if err != nil {
		t.Errorf("Authenticate returned unexpected error: %v", err)
	}
	if !authenticated {
		t.Error("Authentication failed after concurrent access")
	}

	perms, err := provider.GetUserPermissions(username)
	if err != nil {
		t.Errorf("GetUserPermissions returned unexpected error: %v", err)
	}
	if len(perms) == 0 {
		t.Error("No permissions found after concurrent access")
	}
}
