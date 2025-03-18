package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/wemcdonald/secure_sqlite"
	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

func main() {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "secure_sqlite_example_*.db")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Create a memory auth provider
	memoryAuth := auth.NewMemoryProvider()

	// Create the secure database
	db, err := secure_sqlite.Open(tmpFile.Name(), memoryAuth, "admin", "admin-token")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create users
	adminUser := "admin"
	adminToken := "admin-token"
	user1 := "alice"
	user1Token := "alice-token"
	user2 := "bob"
	user2Token := "bob-token"

	memoryAuth.AddUser(adminUser, adminToken)
	memoryAuth.AddUser(user1, user1Token)
	memoryAuth.AddUser(user2, user2Token)

	// Create roles
	adminRoleID, err := db.CreateRole("admin")
	if err != nil {
		log.Fatal(err)
	}
	userRoleID, err := db.CreateRole("user")
	if err != nil {
		log.Fatal(err)
	}

	// Assign roles to users
	err = db.AssignRoleToUser(adminUser, "admin")
	if err != nil {
		log.Fatal(err)
	}
	err = db.AssignRoleToUser(user1, "user")
	if err != nil {
		log.Fatal(err)
	}
	err = db.AssignRoleToUser(user2, "user")
	if err != nil {
		log.Fatal(err)
	}

	// Create test tables
	_, err = db.Exec(adminUser, adminToken, `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP NOT NULL,
			department TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Grant permissions to roles
	// Admin has full access
	err = db.GrantTablePermission(adminRoleID, "users", permissions.TablePermission)
	if err != nil {
		log.Fatal(err)
	}

	// Users can only select their own department's data
	err = db.GrantTablePermission(userRoleID, "users", permissions.TablePermission)
	if err != nil {
		log.Fatal(err)
	}
	err = db.GrantColumnPermission(userRoleID, "users", "email", permissions.ColumnPermission)
	if err != nil {
		log.Fatal(err)
	}
	err = db.GrantRowPermission(userRoleID, "users", "department = current_user_department()", permissions.RowPermission)
	if err != nil {
		log.Fatal(err)
	}

	// Insert test data
	_, err = db.Exec(adminUser, adminToken, `
		INSERT INTO users (name, email, created_at, department)
		VALUES 
			('Alice Smith', 'alice@example.com', ?, 'Engineering'),
			('Bob Johnson', 'bob@example.com', ?, 'Marketing'),
			('Charlie Brown', 'charlie@example.com', ?, 'Engineering')
	`, time.Now(), time.Now(), time.Now())
	if err != nil {
		log.Fatal(err)
	}

	// Test admin access (should see all users)
	fmt.Println("\nAdmin view (all users):")
	rows, err := db.Query(adminUser, adminToken, "SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var name, email, department string
		var createdAt time.Time
		err := rows.Scan(&id, &name, &email, &createdAt, &department)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User: %s (%s) - Department: %s\n", name, email, department)
	}

	// Test user access (should only see users in their department)
	fmt.Println("\nUser view (department-filtered):")
	rows, err = db.Query(user1, user1Token, "SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var name, email, department string
		var createdAt time.Time
		err := rows.Scan(&id, &name, &email, &createdAt, &department)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User: %s (%s) - Department: %s\n", name, email, department)
	}

	// Test column-level permissions
	fmt.Println("\nTesting column-level permissions:")
	rows, err = db.Query(user1, user1Token, "SELECT id, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var email string
		err := rows.Scan(&id, &email)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User ID: %d, Email: %s\n", id, email)
	}

	fmt.Println("\nExample completed successfully")
}
