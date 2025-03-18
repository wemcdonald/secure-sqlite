# Secure SQLite Wrapper

This package provides a secure wrapper around the SQLite database with built-in authentication and role-based access control (RBAC). It implements a subset of the standard `database/sql` interface while enforcing security at every operation.

The package includes a simple in-memory authentication provider for demonstration purposes, but this can be extended to support table-based authentication or external auth providers (LDAP, OAuth, etc.) by implementing the `auth.Provider` interface.

## Features

- Connection-level authentication
- Role-based access control (RBAC)
- Table, column, and row-level permissions
- Standard `database/sql` compatible interface
- Extensible authentication provider interface
- Thread-safe operations

## Installation

```bash
go get github.com/wemcdonald/secure-sqlite
```

## Basic Usage

```go
package main

import (
    "log"
    "github.com/wemcdonald/secure-sqlite"
    "github.com/wemcdonald/secure-sqlite/pkg/auth"
    "github.com/wemcdonald/secure-sqlite/pkg/permissions"
)

func main() {
    // Create an authentication provider
    authProvider := auth.NewMemoryProvider()

    // Add a user
    username := "admin"
    token := "secret-token"
    authProvider.AddUser(username, token)

    // Create a new secure database instance with authentication
    db, err := secure_sqlite.Open("database.db", authProvider, username, token)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create a role
    roleID, err := db.CreateRole("admin")
    if err != nil {
        log.Fatal(err)
    }

    // Assign role to user
    err = db.AssignRoleToUser(username, "admin")
    if err != nil {
        log.Fatal(err)
    }

    // Grant permissions to role
    err = db.GrantTablePermission(roleID, "users", permissions.TablePermission)
    if err != nil {
        log.Fatal(err)
    }

    // Execute standard SQL operations
    rows, err := db.Query("SELECT * FROM users")
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    // Process results...
}
```

## Supported SQL Operations

The package implements the following standard SQL operations from `database/sql`:

- `Query(query string, args ...interface{}) (*sql.Rows, error)`
- `QueryRow(query string, args ...interface{}) *sql.Row`
- `Exec(query string, args ...interface{}) (sql.Result, error)`
- `Prepare(query string) (*sql.Stmt, error)`
- `Begin() (*sql.Tx, error)`
- `Ping() error`

Each operation enforces the configured permissions before executing.

## Permission Levels

### Table-Level Permissions

```go
// Grant table-level permission to role
err = db.GrantTablePermission(roleID, "users", permissions.TablePermission)
if err != nil {
    log.Fatal(err)
}
```

### Column-Level Permissions

```go
// Grant column-level permission to role
err = db.GrantColumnPermission(roleID, "users", "email", permissions.ColumnPermission)
if err != nil {
    log.Fatal(err)
}
```

### Row-Level Permissions

```go
// Grant row-level permission with conditions
err = db.GrantRowPermission(roleID, "users", "id >= 0", permissions.Select)
if err != nil {
    log.Fatal(err)
}
```

## Transaction Support

The package supports SQL transactions with permission checks on each operation:

```go
// Start a transaction
tx, err := db.Begin()
if err != nil {
    log.Fatal(err)
}

// Execute operations within transaction
_, err = tx.Exec("INSERT INTO users (name) VALUES (?)", "John")
if err != nil {
    tx.Rollback()
    log.Fatal(err)
}

// Commit the transaction
err = tx.Commit()
if err != nil {
    log.Fatal(err)
}
```

## Security Considerations

- Authentication is performed at the connection level
- All operations enforce RBAC permissions
- Table, column, and row-level permissions are checked for each operation
- SQL injection prevention through query validation
- Thread-safe operations for concurrent access
- Transactions maintain permission checks throughout their lifecycle
