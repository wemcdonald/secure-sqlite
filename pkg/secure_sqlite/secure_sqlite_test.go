package secure_sqlite

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

func setupTestDB(t *testing.T) (*SecureSQLite, string, func()) {
	tmpFile, err := os.CreateTemp("", "secure_sqlite_test_*.db")
	if err != nil {
		t.Fatal(err)
	}

	mockAuth := auth.NewMemoryProvider()
	username := "testuser"
	token := "testtoken"
	mockAuth.AddUser(username, token)

	db, err := Open(tmpFile.Name(), mockAuth, username, token)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(tmpFile.Name())
	}

	return db, tmpFile.Name(), cleanup
}

func TestOpen(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	assert.NotNil(t, db)
	assert.NotNil(t, db.SqlDB)
	assert.NotNil(t, db.authProvider)
	assert.NotNil(t, db.RBACManager)
	assert.Equal(t, "testuser", db.username)
	assert.Equal(t, "testtoken", db.token)
}

func TestRBACOperations(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	roleID, err := db.CreateRole("admin")
	assert.NoError(t, err)
	assert.Greater(t, roleID, int64(0))

	exists, err := db.RoleExists("admin")
	assert.NoError(t, err)
	assert.True(t, exists)

	permID, err := db.CreatePermission("read")
	assert.NoError(t, err)
	assert.Greater(t, permID, int64(0))

	err = db.AssignPermissionToRole("admin", "read")
	assert.NoError(t, err)

	hasPerm, err := db.RoleHasPermission("admin", "read")
	assert.NoError(t, err)
	assert.True(t, hasPerm)

	err = db.GrantTablePermission(roleID, "users", permissions.TablePermission)
	assert.NoError(t, err)
}

func TestQueryOperations(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	mockAuth := db.authProvider.(*auth.MemoryProvider)
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "id",
	})
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "name",
	})
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "created_at",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:      permissions.RowPermission,
		Table:     "test_table",
		Column:    "id",
		Condition: "id >= 0",
	})

	_, err := db.Exec(`
		CREATE TABLE test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)
	`)
	assert.NoError(t, err)

	result, err := db.Exec(`
		INSERT INTO test_table (name, created_at)
		VALUES (?, ?)
	`, "test", time.Now())
	assert.NoError(t, err)
	rowsAffected, err := result.RowsAffected()
	assert.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	rows, err := db.Query("SELECT * FROM test_table")
	assert.NoError(t, err)
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	assert.Equal(t, 1, count)
}

func TestAuthentication(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secure_sqlite_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	mockAuth := auth.NewMemoryProvider()
	username := "testuser"
	token := "testtoken"
	mockAuth.AddUser(username, token)

	// Test successful authentication
	db, err := Open(tmpFile.Name(), mockAuth, username, token)
	assert.NoError(t, err)
	assert.NotNil(t, db)
	db.Close()

	// Test failed authentication
	db, err = Open(tmpFile.Name(), mockAuth, username, "wrongtoken")
	assert.Error(t, err)
	assert.Nil(t, db)
}

func TestErrorHandling(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Query("SELECT * FROM nonexistent_table")
	assert.Error(t, err)
	assert.IsType(t, &DBError{}, err)
}

func TestQueryRow(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	mockAuth := db.authProvider.(*auth.MemoryProvider)
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "id",
	})
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "name",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:      permissions.RowPermission,
		Table:     "test_table",
		Condition: "id >= 0",
		Action:    permissions.Select,
	})

	// Create test table
	_, err := db.Exec(`
		CREATE TABLE test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	assert.NoError(t, err)

	// Insert test data
	_, err = db.Exec(`
		INSERT INTO test_table (name)
		VALUES (?)
	`, "test")
	assert.NoError(t, err)

	// Test successful query
	var id int
	var name string
	err = db.QueryRow("SELECT id, name FROM test_table WHERE id = 1").Scan(&id, &name)
	assert.NoError(t, err)
	assert.Equal(t, 1, id)
	assert.Equal(t, "test", name)

	// Test permission denied
	err = mockAuth.UpdateUserPermissions(db.username, []permissions.Permission{})
	assert.NoError(t, err)
	err = db.QueryRow("SELECT id, name FROM test_table WHERE id = 1").Scan(&id, &name)
	assert.Error(t, err)
	assert.Equal(t, sql.ErrNoRows, err)
}

func TestPrepare(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	mockAuth := db.authProvider.(*auth.MemoryProvider)
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "id",
	})
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "name",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:      permissions.RowPermission,
		Table:     "test_table",
		Condition: "id >= 0",
		Action:    permissions.Insert,
	})

	// Create test table
	_, err := db.Exec(`
		CREATE TABLE test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	assert.NoError(t, err)

	// Test successful prepare
	stmt, err := db.Prepare("INSERT INTO test_table (name) VALUES (?)")
	assert.NoError(t, err)
	defer stmt.Close()

	// Test permission denied
	err = mockAuth.UpdateUserPermissions(db.username, []permissions.Permission{})
	assert.NoError(t, err)
	_, err = db.Prepare("INSERT INTO test_table (name) VALUES (?)")
	assert.Error(t, err)
	assert.IsType(t, &DBError{}, err)
}

func TestTransaction(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	mockAuth := db.authProvider.(*auth.MemoryProvider)
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:  permissions.TablePermission,
		Table: "test_table",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "id",
	})
	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:   permissions.ColumnPermission,
		Table:  "test_table",
		Column: "name",
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:      permissions.RowPermission,
		Table:     "test_table",
		Condition: "id >= 0",
		Action:    permissions.Insert,
	})

	mockAuth.AddPermission(db.username, permissions.Permission{
		Type:      permissions.RowPermission,
		Table:     "test_table",
		Condition: "id >= 0",
		Action:    permissions.Select,
	})

	// Create test table
	_, err := db.Exec(`
		CREATE TABLE test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	assert.NoError(t, err)

	// Test successful transaction
	tx, err := db.Begin()
	assert.NoError(t, err)
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO test_table (name) VALUES (?)", "test1")
	assert.NoError(t, err)

	_, err = tx.Exec("INSERT INTO test_table (name) VALUES (?)", "test2")
	assert.NoError(t, err)

	err = tx.Commit()
	assert.NoError(t, err)

	// Verify the data
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM test_table").Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestPing(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	err := db.Ping()
	assert.NoError(t, err)
}
