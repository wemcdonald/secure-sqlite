package sqlparser

import (
	"fmt"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/wemcdonald/secure_sqlite/pkg/rbac"
	"github.com/xwb1989/sqlparser"
)

// PermissionValidator handles SQL query permission validation
type PermissionValidator struct {
	AuthProvider auth.Provider
	rbacManager  *rbac.RBACManager
}

// NewPermissionValidator creates a new permission validator
func NewPermissionValidator(authProvider auth.Provider) *PermissionValidator {
	return &PermissionValidator{
		AuthProvider: authProvider,
		rbacManager:  rbac.NewRBACManager(authProvider),
	}
}

// getStatementType determines the type of SQL statement
func getStatementType(stmt sqlparser.Statement) StatementType {
	switch stmt.(type) {
	case *sqlparser.Select:
		return StatementSelect
	case *sqlparser.Insert:
		return StatementInsert
	case *sqlparser.Update:
		return StatementUpdate
	case *sqlparser.Delete:
		return StatementDelete
	case *sqlparser.DDL:
		// Handle DDL statements (CREATE, ALTER, DROP)
		ddl := stmt.(*sqlparser.DDL)
		switch ddl.Action {
		case sqlparser.CreateStr:
			return StatementCreate
		case sqlparser.AlterStr:
			return StatementAlter
		case sqlparser.DropStr:
			return StatementDrop
		default:
			return StatementSelect
		}
	default:
		return StatementSelect
	}
}

// ValidatePermissions checks if the user has permission to execute the statement
func (v *PermissionValidator) ValidatePermissions(stmt sqlparser.Statement, username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Parse the statement to get tables and columns
	parser := NewSQLParser()
	parsedStmt, err := parser.Parse(sqlparser.String(stmt))
	if err != nil {
		return fmt.Errorf("failed to parse statement: %w", err)
	}

	// Get the required action based on statement type
	stmtType := getStatementType(stmt)
	requiredAction := v.getRequiredAction(stmtType)

	// Check if user has the required action permission for each table
	for _, tableName := range parsedStmt.Tables {
		hasPermission, err := v.rbacManager.CheckPermission(username, tableName, requiredAction)
		if err != nil {
			return err
		}
		if !hasPermission {
			return fmt.Errorf("no %v permission on table %s", requiredAction, tableName)
		}

		// For SELECT statements, also check column permissions
		if stmtType == StatementSelect {
			for _, col := range parsedStmt.Columns {
				if col == "*" {
					continue // Table permission is sufficient for SELECT *
				}
				hasPermission, err := v.rbacManager.CheckColumnPermission(username, tableName, col)
				if err != nil {
					return err
				}
				if !hasPermission {
					return fmt.Errorf("no permission on column %s in table %s", col, tableName)
				}
			}
		}
	}

	return nil
}

// getRequiredAction returns the action required for a given statement type
func (v *PermissionValidator) getRequiredAction(stmtType StatementType) permissions.Action {
	switch stmtType {
	case StatementSelect:
		return permissions.Select
	case StatementInsert:
		return permissions.Insert
	case StatementUpdate:
		return permissions.Update
	case StatementDelete:
		return permissions.Delete
	case StatementCreate:
		return permissions.Create
	case StatementAlter:
		return permissions.Alter
	case StatementDrop:
		return permissions.Drop
	default:
		return permissions.Select // Default to Select as a safe fallback
	}
}
