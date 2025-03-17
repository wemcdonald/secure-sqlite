package tests

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/wemcdonald/secure_sqlite/internal/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/secure_sqlite"
)

func setupTestDB(t *testing.T) (*secure_sqlite.SecureDB, string, func()) {
	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "secure_sqlite_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a mock auth provider
	mockAuth := &auth.MockProvider{}

	// Create the secure database
	config := secure_sqlite.Config{
		DBPath:       dbPath,
		AuthProvider: mockAuth,
	}

	db, err := secure_sqlite.NewSecureDB(config)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create secure database: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, dbPath, cleanup
}

func TestNewSecureDB(t *testing.T) {
	tests := []struct {
		name    string
		config  secure_sqlite.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: secure_sqlite.Config{
				DBPath:       "test.db",
				AuthProvider: &auth.MockProvider{},
			},
			wantErr: false,
		},
		{
			name: "missing db path",
			config: secure_sqlite.Config{
				AuthProvider: &auth.MockProvider{},
			},
			wantErr: true,
		},
		{
			name: "missing auth provider",
			config: secure_sqlite.Config{
				DBPath: "test.db",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := secure_sqlite.NewSecureDB(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSecureDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && db == nil {
				t.Error("NewSecureDB() returned nil without error")
			}
			if db != nil {
				db.Close()
			}
		})
	}
}

func TestUserManagement(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	// Test user creation
	username := "testuser"
	token := "testtoken"

	// Create user
	err := db.CreateUser(username, token)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test user authentication
	authenticated, err := db.Authenticate(username, token)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}
	if !authenticated {
		t.Error("Valid credentials failed authentication")
	}

	// Test invalid credentials
	authenticated, err = db.Authenticate(username, "wrongtoken")
	if err != nil {
		t.Fatalf("Authentication check failed: %v", err)
	}
	if authenticated {
		t.Error("Invalid credentials passed authentication")
	}
}

func TestSessionManagement(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	username := "testuser"
	token := "testtoken"

	// Create user
	err := db.CreateUser(username, token)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test session creation
	session, err := db.CreateSession(username, token)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session == nil {
		t.Error("Session creation returned nil session")
	}

	// Test session validation
	valid, err := db.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}
	if !valid {
		t.Error("Valid session failed validation")
	}

	// Test session termination
	err = db.TerminateSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to terminate session: %v", err)
	}

	// Verify session is terminated
	valid, err = db.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}
	if valid {
		t.Error("Terminated session passed validation")
	}
}

func TestConnectionPooling(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	username := "testuser"
	token := "testtoken"

	// Create user
	err := db.CreateUser(username, token)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test concurrent connections
	concurrent := 5
	done := make(chan bool)
	for i := 0; i < concurrent; i++ {
		go func() {
			session, err := db.CreateSession(username, token)
			if err != nil {
				t.Errorf("Failed to create session: %v", err)
				done <- false
				return
			}
			defer db.TerminateSession(session.ID)

			// Execute a simple query
			_, err = db.Query(username, token, "SELECT 1")
			if err != nil {
				t.Errorf("Query failed: %v", err)
				done <- false
				return
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrent; i++ {
		if !<-done {
			t.Fatal("One or more concurrent operations failed")
		}
	}
}

func TestDatabaseOperations(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	username := "testuser"
	token := "testtoken"

	// Create user
	err := db.CreateUser(username, token)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create test table
	_, err = db.Exec(username, token, `
		CREATE TABLE test (
			id INTEGER PRIMARY KEY,
			name TEXT
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Test insert
	result, err := db.Exec(username, token, "INSERT INTO test (name) VALUES (?)", "test1")
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}
	if rows != 1 {
		t.Errorf("Expected 1 row affected, got %d", rows)
	}

	// Test select
	var queryRows *sql.Rows
	queryRows, err = db.Query(username, token, "SELECT COUNT(*) FROM test")
	if err != nil {
		t.Fatalf("Failed to query: %v", err)
	}
	defer queryRows.Close()

	var count int64
	if queryRows.Next() {
		err = queryRows.Scan(&count)
		if err != nil {
			t.Fatalf("Failed to scan count: %v", err)
		}
	}
	if count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}
}
