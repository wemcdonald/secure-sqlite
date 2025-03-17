package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/wemcdonald/secure_sqlite/internal/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/secure_sqlite"
)

func main() {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "secure_sqlite_example_*.db")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Create a mock auth provider
	mockAuth := &auth.MockProvider{}

	// Create the secure database
	config := secure_sqlite.Config{
		DBPath:       tmpFile.Name(),
		AuthProvider: mockAuth,
	}

	db, err := secure_sqlite.NewSecureDB(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create a user
	username := "alice"
	token := "secret-token"
	err = db.CreateUser(username, token)
	if err != nil {
		log.Fatal(err)
	}

	// Create a session
	session, err := db.CreateSession(username, token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created session: %s\n", session.ID)

	// Create a test table
	_, err = db.Exec(username, token, `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Insert some data
	_, err = db.Exec(username, token, `
		INSERT INTO users (name, email, created_at)
		VALUES (?, ?, ?)
	`, "Alice Smith", "alice@example.com", time.Now())
	if err != nil {
		log.Fatal(err)
	}

	// Query the data
	rows, err := db.Query(username, token, "SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Print results
	for rows.Next() {
		var id int64
		var name, email string
		var createdAt time.Time
		err := rows.Scan(&id, &name, &email, &createdAt)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User: %s (%s)\n", name, email)
	}

	// Terminate the session
	err = db.TerminateSession(session.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Session terminated")
}
