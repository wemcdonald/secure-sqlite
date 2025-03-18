// Package secure_sqlite provides a secure SQLite database wrapper with authentication and RBAC.
package secure_sqlite

import (
	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/secure_sqlite"
)

// Open creates a new secure SQLite database connection
func Open(dataSourceName string, authProvider auth.Provider, username, token string) (*secure_sqlite.SecureSQLite, error) {
	return secure_sqlite.Open(dataSourceName, authProvider, username, token)
}

// Re-export types for convenience
type (
	SecureSQLite = secure_sqlite.SecureSQLite
	DBError      = secure_sqlite.DBError
)
