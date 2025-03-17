# Secure SQLite Wrapper

This package provides a secure wrapper around the SQLite database with built-in authentication and authorization capabilities.

## Features

- Authentication for database operations
- Permission-based access control
- Extensible authentication provider interface
- Thread-safe operations

## Installation

```bash
go get github.com/wemcdonald/secure-sqlite
```

## Usage

```go
package main

import (
    "log"
    "github.com/wemcdonald/secure-sqlite"
    "github.com/wemcdonald/secure-sqlite/auth"
)

func main() {
    // Create an authentication provider
    authProvider := auth.NewMemoryAuthProvider()

    // Add a user with permissions
    authProvider.AddUser("admin", "token123", []string{"read", "write"})

    // Create a new secure database instance
    config := secure_sqlite.Config{
        DBPath:       "database.db",
        AuthProvider: authProvider,
    }

    db, err := secure_sqlite.NewSecureDB(config)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Execute queries with authentication
    rows, err := db.Query("admin", "token123", "SELECT * FROM users")
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    // Process results...
}
```

## Security Considerations

- This is a basic implementation and should be enhanced with:
  - SQL injection prevention
  - Query validation
  - Rate limiting
  - Audit logging
  - Secure session management

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
