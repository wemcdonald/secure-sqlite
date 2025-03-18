package sqlparser

import (
	"fmt"
	"strings"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/xwb1989/sqlparser"
)

// SecurityTransformer handles SQL query transformation for security
type SecurityTransformer struct {
	AuthProvider auth.Provider
	currentStmt  sqlparser.Statement
}

// NewSecurityTransformer creates a new security transformer
func NewSecurityTransformer(authProvider auth.Provider) *SecurityTransformer {
	return &SecurityTransformer{
		AuthProvider: authProvider,
	}
}

// TransformQuery transforms a SQL query based on user permissions
func (t *SecurityTransformer) TransformQuery(stmt sqlparser.Statement, userID int64) (string, error) {
	if stmt == nil {
		return "", fmt.Errorf("statement cannot be nil")
	}
	t.currentStmt = stmt
	switch stmt.(type) {
	case *sqlparser.Select:
		// Get user permissions from auth provider
		userPerms, err := t.AuthProvider.GetUserPermissions(fmt.Sprintf("user_%d", userID))
		if err != nil {
			return "", fmt.Errorf("failed to get user permissions: %w", err)
		}

		// Check if user has any row-level permissions
		hasRowPermission := false
		for _, perm := range userPerms {
			if perm.Type == permissions.RowPermission {
				hasRowPermission = true
				break
			}
		}

		// If no row-level permissions, return original query
		if !hasRowPermission {
			return sqlparser.String(stmt), nil
		}

		// Apply row-level security transformations
		if err := t.addSelectSecurity(stmt, userID); err != nil {
			return "", err
		}
		return sqlparser.String(stmt), nil
	case *sqlparser.Update:
		if err := t.addUpdateSecurity(stmt, userID); err != nil {
			return "", err
		}
		return sqlparser.String(stmt), nil
	case *sqlparser.Delete:
		if err := t.addDeleteSecurity(stmt, userID); err != nil {
			return "", err
		}
		return sqlparser.String(stmt), nil
	default:
		return sqlparser.String(stmt), nil
	}
}

// addSelectSecurity adds row-level security conditions to SELECT statements
func (t *SecurityTransformer) addSelectSecurity(ast sqlparser.Statement, userID int64) error {
	selectStmt, ok := ast.(*sqlparser.Select)
	if !ok {
		return fmt.Errorf("expected SELECT statement")
	}

	// Get row-level security conditions for each table
	var conditions []string
	for _, table := range t.getTablesFromSelect(selectStmt) {
		condition, err := t.getRowLevelSecurityConditions(table, userID)
		if err != nil {
			return err
		}
		if condition != "" {
			conditions = append(conditions, condition)
		}
	}

	if len(conditions) > 0 {
		// Parse the conditions into an expression by wrapping it in a SELECT
		conditionStmt, err := sqlparser.Parse(fmt.Sprintf("SELECT * FROM dual WHERE %s", strings.Join(conditions, " AND ")))
		if err != nil {
			return fmt.Errorf("failed to parse security conditions: %v", err)
		}
		conditionExpr := conditionStmt.(*sqlparser.Select).Where.Expr

		// Add the conditions to the WHERE clause
		if selectStmt.Where == nil {
			selectStmt.Where = &sqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			// Combine with existing WHERE clause
			selectStmt.Where.Expr = &sqlparser.AndExpr{
				Left:  selectStmt.Where.Expr,
				Right: conditionExpr,
			}
		}
	}

	return nil
}

// addUpdateSecurity adds row-level security conditions to UPDATE statements
func (t *SecurityTransformer) addUpdateSecurity(ast sqlparser.Statement, userID int64) error {
	updateStmt, ok := ast.(*sqlparser.Update)
	if !ok {
		return fmt.Errorf("expected UPDATE statement")
	}

	// Get row-level security conditions for the target table
	aliasedTableExpr, ok := updateStmt.TableExprs[0].(*sqlparser.AliasedTableExpr)
	if !ok {
		return fmt.Errorf("expected AliasedTableExpr")
	}
	tableName, ok := aliasedTableExpr.Expr.(sqlparser.TableName)
	if !ok {
		return fmt.Errorf("expected TableName")
	}
	table := tableName.Name.String()

	conditions, err := t.getRowLevelSecurityConditions(table, userID)
	if err != nil {
		return err
	}
	if conditions != "" {
		// Parse the conditions into an expression by wrapping it in a SELECT
		conditionStmt, err := sqlparser.Parse(fmt.Sprintf("SELECT * FROM dual WHERE %s", conditions))
		if err != nil {
			return fmt.Errorf("failed to parse security conditions: %v", err)
		}
		conditionExpr := conditionStmt.(*sqlparser.Select).Where.Expr

		// Add the conditions to the WHERE clause
		if updateStmt.Where == nil {
			updateStmt.Where = &sqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			// Combine with existing WHERE clause
			updateStmt.Where.Expr = &sqlparser.AndExpr{
				Left:  updateStmt.Where.Expr,
				Right: conditionExpr,
			}
		}
	}

	return nil
}

// addDeleteSecurity adds row-level security conditions to DELETE statements
func (t *SecurityTransformer) addDeleteSecurity(ast sqlparser.Statement, userID int64) error {
	deleteStmt, ok := ast.(*sqlparser.Delete)
	if !ok {
		return fmt.Errorf("expected DELETE statement")
	}

	// Get row-level security conditions for the target table
	aliasedTableExpr, ok := deleteStmt.TableExprs[0].(*sqlparser.AliasedTableExpr)
	if !ok {
		return fmt.Errorf("expected AliasedTableExpr")
	}
	tableName, ok := aliasedTableExpr.Expr.(sqlparser.TableName)
	if !ok {
		return fmt.Errorf("expected TableName")
	}
	table := tableName.Name.String()

	conditions, err := t.getRowLevelSecurityConditions(table, userID)
	if err != nil {
		return err
	}
	if conditions != "" {
		// Parse the conditions into an expression by wrapping it in a SELECT
		conditionStmt, err := sqlparser.Parse(fmt.Sprintf("SELECT * FROM dual WHERE %s", conditions))
		if err != nil {
			return fmt.Errorf("failed to parse security conditions: %v", err)
		}
		conditionExpr := conditionStmt.(*sqlparser.Select).Where.Expr

		// Add the conditions to the WHERE clause
		if deleteStmt.Where == nil {
			deleteStmt.Where = &sqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			// Combine with existing WHERE clause
			deleteStmt.Where.Expr = &sqlparser.AndExpr{
				Left:  deleteStmt.Where.Expr,
				Right: conditionExpr,
			}
		}
	}

	return nil
}

// getTablesFromSelect extracts table names from a SELECT statement
func (t *SecurityTransformer) getTablesFromSelect(selectStmt *sqlparser.Select) []string {
	tables := make([]string, 0)
	for _, tableExpr := range selectStmt.From {
		switch expr := tableExpr.(type) {
		case *sqlparser.AliasedTableExpr:
			if tableName, ok := expr.Expr.(sqlparser.TableName); ok {
				tables = append(tables, tableName.Name.String())
			}
		case *sqlparser.JoinTableExpr:
			if left, ok := expr.LeftExpr.(*sqlparser.AliasedTableExpr); ok {
				if tableName, ok := left.Expr.(sqlparser.TableName); ok {
					tables = append(tables, tableName.Name.String())
				}
			}
			if right, ok := expr.RightExpr.(*sqlparser.AliasedTableExpr); ok {
				if tableName, ok := right.Expr.(sqlparser.TableName); ok {
					tables = append(tables, tableName.Name.String())
				}
			}
		}
	}
	return tables
}

// getRowLevelSecurityConditions gets the row-level security conditions for a table and user
func (t *SecurityTransformer) getRowLevelSecurityConditions(table string, userID int64) (string, error) {
	if table == "" {
		return "", fmt.Errorf("table name cannot be empty")
	}
	if userID <= 0 {
		return "", fmt.Errorf("invalid user ID: %d", userID)
	}

	// Get user permissions from auth provider
	userPerms, err := t.AuthProvider.GetUserPermissions(fmt.Sprintf("user_%d", userID))
	if err != nil {
		return "", fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Find row-level security permission for the table
	for _, perm := range userPerms {
		if perm.Type == permissions.RowPermission && perm.Table == table {
			// Get the table alias from the condition
			alias := t.getTableAlias(table)
			if alias != "" {
				// Replace table name with alias in the condition
				return strings.ReplaceAll(perm.Condition, "user_id", alias+".user_id"), nil
			}
			return perm.Condition, nil
		}
	}

	return "", nil // No row-level security for this table
}

// getTableAlias returns the alias for a table in the current statement
func (t *SecurityTransformer) getTableAlias(table string) string {
	switch stmt := t.currentStmt.(type) {
	case *sqlparser.Select:
		for _, tableExpr := range stmt.From {
			switch expr := tableExpr.(type) {
			case *sqlparser.AliasedTableExpr:
				if tableName, ok := expr.Expr.(sqlparser.TableName); ok && tableName.Name.String() == table {
					if !expr.As.IsEmpty() {
						return expr.As.String()
					}
				}
			case *sqlparser.JoinTableExpr:
				if left, ok := expr.LeftExpr.(*sqlparser.AliasedTableExpr); ok {
					if tableName, ok := left.Expr.(sqlparser.TableName); ok && tableName.Name.String() == table {
						if !left.As.IsEmpty() {
							return left.As.String()
						}
					}
				}
				if right, ok := expr.RightExpr.(*sqlparser.AliasedTableExpr); ok {
					if tableName, ok := right.Expr.(sqlparser.TableName); ok && tableName.Name.String() == table {
						if !right.As.IsEmpty() {
							return right.As.String()
						}
					}
				}
			}
		}
	}
	return ""
}
