package sqlparser

import (
	"github.com/xwb1989/sqlparser"
)

// StatementType represents the type of SQL statement
type StatementType int

const (
	StatementUnknown StatementType = iota
	StatementSelect
	StatementInsert
	StatementUpdate
	StatementDelete
	StatementCreate
	StatementAlter
	StatementDrop
)

// String implements the Stringer interface for StatementType
func (s StatementType) String() string {
	switch s {
	case StatementSelect:
		return "SELECT"
	case StatementInsert:
		return "INSERT"
	case StatementUpdate:
		return "UPDATE"
	case StatementDelete:
		return "DELETE"
	case StatementCreate:
		return "CREATE"
	case StatementAlter:
		return "ALTER"
	case StatementDrop:
		return "DROP"
	default:
		return "UNKNOWN"
	}
}

// SQLStatement represents a parsed SQL statement
type SQLStatement struct {
	Type    StatementType
	Tables  []string
	Columns []string
	Where   string
	AST     sqlparser.Statement // Using concrete type instead of interface{}
}
