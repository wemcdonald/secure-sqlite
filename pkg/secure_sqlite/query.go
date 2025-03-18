package secure_sqlite

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/wemcdonald/secure_sqlite/pkg/sqlparser"
	xsqlparser "github.com/xwb1989/sqlparser"
)

// Query executes a SELECT query with RBAC checks
func (db *SecureSQLite) Query(query string, args ...interface{}) (*sql.Rows, error) {
	// Get the action type
	action, err := db.getActionType(query)
	if err != nil {
		return nil, err
	}

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
		hasPermission, err := db.RBACManager.HasTablePermission(db.username, table, db.getPermissionType(action))
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
			hasPermission, err := db.RBACManager.HasColumnPermission(db.username, table, col, db.getPermissionType(action))
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
		rowPerms, err := db.RBACManager.GetRowPermissions(db.username, table, db.getPermissionType(action))
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

	// Execute the query
	rows, err := db.SqlDB.Query(query, args...)
	if err != nil {
		return nil, &DBError{
			Code:    "QUERY_ERROR",
			Message: "failed to execute query",
			Err:     err,
		}
	}
	return rows, nil
}

// Exec executes a non-SELECT query with RBAC checks
func (db *SecureSQLite) Exec(query string, args ...interface{}) (sql.Result, error) {
	// Get the action type
	action, err := db.getActionType(query)
	if err != nil {
		return nil, err
	}

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
	case *xsqlparser.DDL:
		// For DDL operations, we'll handle permissions at the database level
		return db.SqlDB.Exec(query, args...)
	}

	// Check table-level permissions
	for _, table := range tables {
		hasPermission, err := db.RBACManager.HasTablePermission(db.username, table, db.getPermissionType(action))
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

	// Check column-level permissions for INSERT/UPDATE
	switch action {
	case permissions.Insert, permissions.Update:
		for _, table := range tables {
			for _, col := range columns {
				hasPermission, err := db.RBACManager.HasColumnPermission(db.username, table, col, db.getPermissionType(action))
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
	}

	// Check row-level permissions
	for _, table := range tables {
		rowPerms, err := db.RBACManager.GetRowPermissions(db.username, table, db.getPermissionType(action))
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

	// Execute the query
	return db.SqlDB.Exec(query, args...)
}

// addRowLevelCondition adds a row-level permission condition to a query
func (db *SecureSQLite) addRowLevelCondition(query, condition string) string {
	// Parse the query using sqlparser
	stmt, err := xsqlparser.Parse(query)
	if err != nil {
		return query // Return original query if parsing fails
	}

	// Parse the condition into an expression
	conditionStmt, err := xsqlparser.Parse(fmt.Sprintf("SELECT * FROM dual WHERE %s", condition))
	if err != nil {
		return query // Return original query if condition parsing fails
	}
	conditionExpr := conditionStmt.(*xsqlparser.Select).Where.Expr

	// Add the condition to the WHERE clause
	switch s := stmt.(type) {
	case *xsqlparser.Select:
		if s.Where == nil {
			s.Where = &xsqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			s.Where.Expr = &xsqlparser.AndExpr{
				Left:  s.Where.Expr,
				Right: conditionExpr,
			}
		}
	case *xsqlparser.Update:
		if s.Where == nil {
			s.Where = &xsqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			s.Where.Expr = &xsqlparser.AndExpr{
				Left:  s.Where.Expr,
				Right: conditionExpr,
			}
		}
	case *xsqlparser.Delete:
		if s.Where == nil {
			s.Where = &xsqlparser.Where{
				Type: "where",
				Expr: conditionExpr,
			}
		} else {
			s.Where.Expr = &xsqlparser.AndExpr{
				Left:  s.Where.Expr,
				Right: conditionExpr,
			}
		}
	}

	return xsqlparser.String(stmt)
}

// getActionType determines the type of action from the SQL query
func (db *SecureSQLite) getActionType(query string) (permissions.Action, error) {
	query = strings.TrimSpace(strings.ToUpper(query))
	switch {
	case strings.HasPrefix(query, "SELECT"):
		return permissions.Select, nil
	case strings.HasPrefix(query, "INSERT"):
		return permissions.Insert, nil
	case strings.HasPrefix(query, "UPDATE"):
		return permissions.Update, nil
	case strings.HasPrefix(query, "DELETE"):
		return permissions.Delete, nil
	case strings.HasPrefix(query, "CREATE"):
		return permissions.Create, nil
	case strings.HasPrefix(query, "DROP"):
		return permissions.Drop, nil
	case strings.HasPrefix(query, "ALTER"):
		return permissions.Alter, nil
	default:
		return permissions.Select, &DBError{
			Code:    "UNSUPPORTED_QUERY",
			Message: fmt.Sprintf("unsupported query type: %s", query),
		}
	}
}

// getPermissionType maps an Action to the appropriate PermissionType
func (db *SecureSQLite) getPermissionType(action permissions.Action) permissions.PermissionType {
	switch action {
	case permissions.Select:
		return permissions.TablePermission
	case permissions.Insert, permissions.Update, permissions.Delete:
		return permissions.TablePermission
	case permissions.Create, permissions.Drop, permissions.Alter:
		return permissions.TablePermission
	default:
		return permissions.TablePermission
	}
}
