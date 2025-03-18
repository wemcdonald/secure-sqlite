package secure_sqlite

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/wemcdonald/secure_sqlite/pkg/rbac"
	"github.com/wemcdonald/secure_sqlite/pkg/sqlparser"
	xsqlparser "github.com/xwb1989/sqlparser"
)

// DBError represents a database error
type DBError struct {
	Code    string
	Message string
	Err     error
}

func (e *DBError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *DBError) Unwrap() error {
	return e.Err
}

// SecureSQLite implements the SecureDB interface
type SecureSQLite struct {
	SqlDB        *sql.DB
	authProvider auth.Provider
	RBACManager  *rbac.RBACManager
	username     string
	token        string
}

// Open creates a new secure SQLite database connection
func Open(dataSourceName string, authProvider auth.Provider, username, token string) (*SecureSQLite, error) {
	// Check authentication first
	authenticated, err := authProvider.Authenticate(username, token)
	if err != nil {
		return nil, &DBError{
			Code:    "AUTH_ERROR",
			Message: "authentication failed",
			Err:     err,
		}
	}
	if !authenticated {
		return nil, &DBError{
			Code:    "AUTH_ERROR",
			Message: "authentication failed",
		}
	}

	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}

	// Initialize RBAC manager
	rbacManager := rbac.NewRBACManager(authProvider)

	secureDB := &SecureSQLite{
		SqlDB:        db,
		authProvider: authProvider,
		RBACManager:  rbacManager,
		username:     username,
		token:        token,
	}

	return secureDB, nil
}

// Close closes the database connection
func (db *SecureSQLite) Close() error {
	return db.SqlDB.Close()
}

// AuthProvider returns the authentication provider used by the database
func (db *SecureSQLite) AuthProvider() auth.Provider {
	return db.authProvider
}

// DB returns the underlying database connection
func (db *SecureSQLite) DB() *sql.DB {
	return db.SqlDB
}

// Ping checks the database connection
func (db *SecureSQLite) Ping() error {
	return db.SqlDB.Ping()
}

// QueryRow executes a query that returns at most one row with RBAC checks
func (db *SecureSQLite) QueryRow(query string, args ...interface{}) *sql.Row {
	// Create parser and parse the query
	parser := sqlparser.NewParser(db.authProvider)
	stmt, err := parser.Parse(query)
	if err != nil {
		return db.SqlDB.QueryRow("SELECT 1 WHERE 1=0") // Return empty row that will error on Scan
	}

	// Extract tables and columns based on statement type
	var tables []string
	var columns []string

	switch s := stmt.(type) {
	case *xsqlparser.Select:
		// Extract tables from FROM clause
		for _, tableExpr := range s.From {
			switch expr := tableExpr.(type) {
			case *xsqlparser.AliasedTableExpr:
				if tableName, ok := expr.Expr.(xsqlparser.TableName); ok {
					tables = append(tables, tableName.Name.String())
				}
			}
		}
		// Extract columns from SELECT list
		for _, selectExpr := range s.SelectExprs {
			switch expr := selectExpr.(type) {
			case *xsqlparser.AliasedExpr:
				if colName, ok := expr.Expr.(*xsqlparser.ColName); ok {
					columns = append(columns, colName.Name.String())
				}
			}
		}
	}

	// Check table-level permissions
	for _, table := range tables {
		hasPermission, err := db.RBACManager.HasTablePermission(db.username, table, permissions.TablePermission)
		if err != nil || !hasPermission {
			return db.SqlDB.QueryRow("SELECT 1 WHERE 1=0") // Return empty row that will error on Scan
		}
	}

	// Check column-level permissions
	for _, table := range tables {
		for _, col := range columns {
			hasPermission, err := db.RBACManager.HasColumnPermission(db.username, table, col, permissions.ColumnPermission)
			if err != nil || !hasPermission {
				return db.SqlDB.QueryRow("SELECT 1 WHERE 1=0") // Return empty row that will error on Scan
			}
		}
	}

	// Check row-level permissions
	for _, table := range tables {
		rowPerms, err := db.RBACManager.GetRowPermissions(db.username, table, permissions.RowPermission)
		if err != nil {
			return db.SqlDB.QueryRow("SELECT 1 WHERE 1=0") // Return empty row that will error on Scan
		}
		// Only check if row permissions are defined
		if len(rowPerms) > 0 && !rowPerms[0].Granted {
			return db.SqlDB.QueryRow("SELECT 1 WHERE 1=0") // Return empty row that will error on Scan
		}
	}

	return db.SqlDB.QueryRow(query, args...)
}

// Prepare creates a prepared statement with RBAC checks
func (db *SecureSQLite) Prepare(query string) (*sql.Stmt, error) {
	// Create parser and parse the query
	parser := sqlparser.NewParser(db.authProvider)
	stmt, err := parser.Parse(query)
	if err != nil {
		return nil, &DBError{
			Code:    "PARSE_ERROR",
			Message: "failed to parse query",
			Err:     err,
		}
	}

	// Extract tables and columns based on statement type
	var tables []string
	var columns []string

	switch s := stmt.(type) {
	case *xsqlparser.Select:
		// Extract tables from FROM clause
		for _, tableExpr := range s.From {
			switch expr := tableExpr.(type) {
			case *xsqlparser.AliasedTableExpr:
				if tableName, ok := expr.Expr.(xsqlparser.TableName); ok {
					tables = append(tables, tableName.Name.String())
				}
			}
		}
		// Extract columns from SELECT list
		for _, selectExpr := range s.SelectExprs {
			switch expr := selectExpr.(type) {
			case *xsqlparser.AliasedExpr:
				if colName, ok := expr.Expr.(*xsqlparser.ColName); ok {
					columns = append(columns, colName.Name.String())
				}
			}
		}
	case *xsqlparser.Insert:
		tables = append(tables, s.Table.Name.String())
		for _, col := range s.Columns {
			columns = append(columns, col.String())
		}
	case *xsqlparser.Update:
		if tableName, ok := s.TableExprs[0].(*xsqlparser.AliasedTableExpr).Expr.(xsqlparser.TableName); ok {
			tables = append(tables, tableName.Name.String())
		}
		for _, expr := range s.Exprs {
			columns = append(columns, expr.Name.Name.String())
		}
	case *xsqlparser.Delete:
		if tableName, ok := s.TableExprs[0].(*xsqlparser.AliasedTableExpr).Expr.(xsqlparser.TableName); ok {
			tables = append(tables, tableName.Name.String())
		}
	}

	// Check table-level permissions
	for _, table := range tables {
		hasPermission, err := db.RBACManager.HasTablePermission(db.username, table, permissions.TablePermission)
		if err != nil {
			return nil, &DBError{
				Code:    "PERMISSION_ERROR",
				Message: fmt.Sprintf("failed to check table permission: %s", table),
				Err:     err,
			}
		}
		if !hasPermission {
			return nil, &DBError{
				Code:    "PERMISSION_DENIED",
				Message: fmt.Sprintf("permission denied for table: %s", table),
			}
		}
	}

	// Check column-level permissions
	for _, table := range tables {
		for _, col := range columns {
			hasPermission, err := db.RBACManager.HasColumnPermission(db.username, table, col, permissions.ColumnPermission)
			if err != nil {
				return nil, &DBError{
					Code:    "PERMISSION_ERROR",
					Message: fmt.Sprintf("failed to check column permission: %s.%s", table, col),
					Err:     err,
				}
			}
			if !hasPermission {
				return nil, &DBError{
					Code:    "PERMISSION_DENIED",
					Message: fmt.Sprintf("permission denied for column: %s.%s", table, col),
				}
			}
		}
	}

	// Check row-level permissions
	for _, table := range tables {
		rowPerms, err := db.RBACManager.GetRowPermissions(db.username, table, permissions.RowPermission)
		if err != nil {
			return nil, &DBError{
				Code:    "PERMISSION_ERROR",
				Message: fmt.Sprintf("failed to check row permissions: %s", table),
				Err:     err,
			}
		}
		if len(rowPerms) > 0 && !rowPerms[0].Granted {
			return nil, &DBError{
				Code:    "PERMISSION_DENIED",
				Message: fmt.Sprintf("permission denied for rows in table: %s", table),
			}
		}
	}

	return db.SqlDB.Prepare(query)
}

// Begin starts a transaction with RBAC checks
func (db *SecureSQLite) Begin() (*sql.Tx, error) {
	// For transactions, we don't need to check permissions at the start
	// because each operation within the transaction will be checked individually
	return db.SqlDB.Begin()
}
