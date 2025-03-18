package sqlparser

import (
	"fmt"

	"github.com/xwb1989/sqlparser"
)

// SQLParser handles the parsing of SQL statements into a structured format
type SQLParser struct{}

// NewSQLParser creates a new SQL parser instance
func NewSQLParser() *SQLParser {
	return &SQLParser{}
}

// Parse parses a SQL query and returns a SQLStatement containing the parsed information.
// It extracts the statement type, tables, columns, and where clause from the query.
// Returns an error if the query is empty or contains unsupported SQL syntax.
func (p *SQLParser) Parse(query string) (*SQLStatement, error) {
	if query == "" {
		return nil, ErrEmptyQuery
	}

	// Parse the SQL query using sqlparser
	ast, err := sqlparser.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}

	// Extract statement type
	var stmtType StatementType
	switch stmt := ast.(type) {
	case *sqlparser.Select:
		stmtType = StatementSelect
	case *sqlparser.Insert:
		stmtType = StatementInsert
	case *sqlparser.Update:
		stmtType = StatementUpdate
	case *sqlparser.Delete:
		stmtType = StatementDelete
	case *sqlparser.DDL:
		switch stmt.Action {
		case "create":
			stmtType = StatementCreate
		case "alter":
			stmtType = StatementAlter
		case "drop":
			stmtType = StatementDrop
		default:
			return nil, fmt.Errorf("%w: unsupported DDL action %s", ErrUnsupportedStatement, stmt.Action)
		}
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedStatement, ast)
	}

	// Extract tables and columns based on statement type
	tables := make([]string, 0)
	columns := make([]string, 0)
	var where string

	switch stmt := ast.(type) {
	case *sqlparser.Select:
		// Extract tables from FROM clause
		if stmt.From != nil {
			tables = p.extractTablesFromTableExprs(stmt.From)
		}

		// Extract columns from SELECT clause
		for _, expr := range stmt.SelectExprs {
			switch e := expr.(type) {
			case *sqlparser.StarExpr:
				columns = append(columns, "*")
			case *sqlparser.AliasedExpr:
				if col, ok := e.Expr.(*sqlparser.ColName); ok {
					columns = append(columns, col.Name.String())
				}
			}
		}
		if stmt.Where != nil {
			where = sqlparser.String(stmt.Where)
		}

	case *sqlparser.Insert:
		tables = append(tables, stmt.Table.Name.String())
		for _, col := range stmt.Columns {
			columns = append(columns, col.String())
		}

	case *sqlparser.Update:
		if stmt.TableExprs != nil {
			tables = p.extractTablesFromTableExprs(stmt.TableExprs)
		}
		for _, expr := range stmt.Exprs {
			columns = append(columns, expr.Name.Name.String())
		}
		if stmt.Where != nil {
			where = sqlparser.String(stmt.Where)
		}

	case *sqlparser.Delete:
		if stmt.TableExprs != nil {
			tables = p.extractTablesFromTableExprs(stmt.TableExprs)
		}
		if stmt.Where != nil {
			where = sqlparser.String(stmt.Where)
		}

	case *sqlparser.DDL:
		tables = append(tables, stmt.Table.Name.String())
		switch stmt.Action {
		case "create":
			if stmt.TableSpec != nil {
				for _, col := range stmt.TableSpec.Columns {
					columns = append(columns, col.Name.String())
				}
			}
		case "alter":
			if stmt.TableSpec != nil {
				for _, col := range stmt.TableSpec.Columns {
					columns = append(columns, col.Name.String())
				}
			}
		case "drop":
			// No columns needed for DROP
		}
	}

	return &SQLStatement{
		Type:    stmtType,
		Tables:  tables,
		Columns: columns,
		Where:   where,
		AST:     ast,
	}, nil
}

// extractTablesFromTableExprs extracts table names from a list of table expressions
func (p *SQLParser) extractTablesFromTableExprs(tableExprs sqlparser.TableExprs) []string {
	tables := make([]string, 0)
	for _, tableExpr := range tableExprs {
		switch table := tableExpr.(type) {
		case *sqlparser.AliasedTableExpr:
			if name, ok := table.Expr.(sqlparser.TableName); ok {
				tables = append(tables, name.Name.String())
			}
		case *sqlparser.JoinTableExpr:
			if left, ok := table.LeftExpr.(*sqlparser.AliasedTableExpr); ok {
				if name, ok := left.Expr.(sqlparser.TableName); ok {
					tables = append(tables, name.Name.String())
				}
			}
			if right, ok := table.RightExpr.(*sqlparser.AliasedTableExpr); ok {
				if name, ok := right.Expr.(sqlparser.TableName); ok {
					tables = append(tables, name.Name.String())
				}
			}
		}
	}
	return tables
}
