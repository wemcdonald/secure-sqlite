package sqlparser

import (
	"fmt"

	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/xwb1989/sqlparser"
)

// ErrEmptyQuery is returned when an empty query is provided
var ErrEmptyQuery = fmt.Errorf("empty query")

// ErrUnsupportedStatement is returned when an unsupported SQL statement is provided
var ErrUnsupportedStatement = fmt.Errorf("unsupported SQL statement")

// Parser handles SQL query parsing and transformation
type Parser struct {
	authProvider auth.Provider
	transformer  *SecurityTransformer
	validator    *PermissionValidator
}

// NewParser creates a new SQL parser with security features
func NewParser(authProvider auth.Provider) *Parser {
	return &Parser{
		authProvider: authProvider,
		transformer:  NewSecurityTransformer(authProvider),
		validator:    NewPermissionValidator(authProvider),
	}
}

// Parse parses a SQL query and returns a parsed statement
func (p *Parser) Parse(query string) (sqlparser.Statement, error) {
	return sqlparser.Parse(query)
}

// TransformQuery transforms a SQL query based on user permissions
func (p *Parser) TransformQuery(stmt sqlparser.Statement, userID int64) (string, error) {
	return p.transformer.TransformQuery(stmt, userID)
}

// ValidatePermissions checks if the user has permission to execute the statement
func (p *Parser) ValidatePermissions(stmt sqlparser.Statement, username string) error {
	return p.validator.ValidatePermissions(stmt, username)
}

// CheckPermission checks if a user has permission for a specific operation
func (p *Parser) CheckPermission(username string, tableName string, requiredPermission permissions.PermissionType) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username cannot be empty")
	}

	// Instead of creating a test query, directly use the RBAC manager
	switch requiredPermission {
	case permissions.TablePermission:
		// For table permissions, check if they have any access to the table
		return p.validator.rbacManager.CheckPermission(username, tableName, permissions.Select)
	case permissions.ColumnPermission:
		// For column permissions, check if they have column-level access
		return p.validator.rbacManager.CheckColumnPermission(username, tableName, "*")
	case permissions.RowPermission:
		// For row permissions, check if they have any row-level conditions
		condition, err := p.validator.rbacManager.GetRowCondition(username, tableName)
		if err != nil {
			return false, err
		}
		return condition != "", nil
	default:
		return false, fmt.Errorf("unsupported permission type: %v", requiredPermission)
	}
}
