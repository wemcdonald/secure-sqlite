// Package secure_sqlite provides a secure wrapper around SQLite3 with authentication
// and authorization capabilities.
//
// Features:
//   - User authentication with token-based security
//   - Session management with expiration
//   - Role-based access control (RBAC)
//   - Row-level security
//   - Audit logging
//
// Example usage:
//
//	config := secure_sqlite.Config{
//		DBPath: "database.db",
//		AuthProvider: myAuthProvider,
//	}
//	db, err := secure_sqlite.NewSecureDB(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer db.Close()
//
//	// Create a user
//	err = db.CreateUser("alice", "secret-token")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Execute a query
//	rows, err := db.Query("alice", "secret-token", "SELECT * FROM users")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer rows.Close()
package secure_sqlite
