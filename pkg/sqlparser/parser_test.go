package sqlparser

import (
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/wemcdonald/secure_sqlite/pkg/auth"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
	"github.com/xwb1989/sqlparser"
)

func setupTestDB(t *testing.T) (auth.Provider, func()) {
	// Create a temporary database file
	tmpfile, err := os.CreateTemp("", "testdb-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// Create a mock auth provider
	mockAuth := auth.NewMemoryProvider()
	mockAuth.AddUser("test_user", "test_token")
	mockAuth.AddUser("user_1", "test_token")

	// Return cleanup function
	cleanup := func() {
		os.Remove(tmpfile.Name())
	}

	return mockAuth, cleanup
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:    "valid select",
			query:   "SELECT * FROM users",
			wantErr: false,
		},
		{
			name:    "invalid query",
			query:   "INVALID SQL",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, err := sqlparser.Parse(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && stmt == nil {
				t.Error("Parse() returned nil statement without error")
			}
		})
	}
}

func TestTransformQuery(t *testing.T) {
	authProvider, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name    string
		query   string
		userID  int64
		want    string
		wantErr bool
		setup   func(ap auth.Provider)
	}{
		{
			name:    "transform select without row-level security",
			query:   "SELECT * FROM users",
			userID:  1,
			want:    "select * from users",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				ap.AddPermission("user_1", permissions.Permission{
					Type:  permissions.TablePermission,
					Table: "users",
				})
			},
		},
		{
			name:    "transform select with where clause",
			query:   "SELECT * FROM users WHERE id = 1",
			userID:  1,
			want:    "select * from users where id = 1",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
			},
		},
		{
			name:    "transform select with join",
			query:   "SELECT u.name, o.order_id FROM users u JOIN orders o ON u.id = o.user_id",
			userID:  1,
			want:    "select u.name, o.order_id from users as u join orders as o on u.id = o.user_id",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "orders",
				})
			},
		},
		{
			name:    "transform update",
			query:   "UPDATE users SET name = 'test' WHERE id = 1",
			userID:  1,
			want:    "update users set name = 'test' where id = 1",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Update,
					Table:  "users",
				})
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.ColumnPermission,
					Action: permissions.Update,
					Table:  "users",
					Column: "name",
				})
			},
		},
		{
			name:    "transform delete",
			query:   "DELETE FROM users WHERE id = 1",
			userID:  1,
			want:    "delete from users where id = 1",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Delete,
					Table:  "users",
				})
			},
		},
		{
			name:    "transform select with invalid user ID",
			query:   "SELECT * FROM users",
			userID:  0,
			want:    "",
			wantErr: true,
			setup:   func(ap auth.Provider) {},
		},
		{
			name:    "transform select with nil statement",
			query:   "",
			userID:  1,
			want:    "",
			wantErr: true,
			setup:   func(ap auth.Provider) {},
		},
		{
			name:    "transform select with complex join and row-level security",
			query:   "SELECT u.name, o.order_id FROM users u JOIN orders o ON u.id = o.user_id",
			userID:  1,
			want:    "select u.name, o.order_id from users as u join orders as o on u.id = o.user_id where o.user_id = 1",
			wantErr: false,
			setup: func(ap auth.Provider) {
				ap.AddUser("user_1", "test_token")
				// Add row-level security
				ap.AddPermission("user_1", permissions.Permission{
					Type:      permissions.RowPermission,
					Action:    permissions.Select,
					Table:     "orders",
					Condition: "user_id = 1",
				})
				// Add table permissions
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "orders",
				})
				// Add column permissions
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.ColumnPermission,
					Action: permissions.Select,
					Table:  "users",
					Column: "name",
				})
				ap.AddPermission("user_1", permissions.Permission{
					Type:   permissions.ColumnPermission,
					Action: permissions.Select,
					Table:  "orders",
					Column: "order_id",
				})
			},
		},
	}

	parser := NewParser(authProvider)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(authProvider)
			}

			var stmt sqlparser.Statement
			var err error

			if tt.query != "" {
				stmt, err = sqlparser.Parse(tt.query)
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
			}

			got, err := parser.TransformQuery(stmt, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransformQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Parse and reformat both SQL strings
			gotAST, err := sqlparser.Parse(got)
			if err != nil {
				t.Errorf("Failed to parse transformed query: %v", err)
				return
			}
			wantAST, err := sqlparser.Parse(tt.want)
			if err != nil {
				t.Errorf("Failed to parse expected query: %v", err)
				return
			}

			normalizedGot := normalizeSQL(sqlparser.String(gotAST))
			normalizedWant := normalizeSQL(sqlparser.String(wantAST))
			if normalizedGot != normalizedWant {
				t.Errorf("TransformQuery() = %v\nwant %v\nnormalized got: %v\nnormalized want: %v",
					got, tt.want, normalizedGot, normalizedWant)
			}
		})
	}
}

// normalizeSQL normalizes a SQL string for comparison by:
// - Converting to uppercase
// - Removing extra whitespace
// - Removing "AS" keywords in table aliases
// - Standardizing quotes
func normalizeSQL(sql string) string {
	sql = strings.ToUpper(sql)
	sql = strings.ReplaceAll(sql, " AS ", " ")
	sql = strings.ReplaceAll(sql, "'", "\"")
	sql = strings.ReplaceAll(sql, "( ", "(")
	sql = strings.ReplaceAll(sql, " )", ")")
	sql = strings.ReplaceAll(sql, "  ", " ")
	sql = strings.TrimSpace(sql)
	return sql
}

func TestValidatePermissions(t *testing.T) {
	authProvider, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name     string
		query    string
		username string
		setup    func(auth.Provider, string)
		wantErr  bool
	}{
		{
			name:     "validate select permission with no permissions",
			query:    "SELECT * FROM users",
			username: "test_user",
			setup:    func(ap auth.Provider, username string) {},
			wantErr:  true,
		},
		{
			name:     "validate select permission with table permission",
			query:    "SELECT * FROM users",
			username: "test_user",
			setup: func(ap auth.Provider, username string) {
				ap.AddPermission(username, permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
				ap.AddPermission(username, permissions.Permission{
					Type:   permissions.ColumnPermission,
					Action: permissions.Select,
					Table:  "users",
					Column: "*",
				})
			},
			wantErr: false,
		},
		{
			name:     "validate update permission with wrong permission",
			query:    "UPDATE users SET name = 'John'",
			username: "test_user",
			setup: func(ap auth.Provider, username string) {
				ap.AddPermission(username, permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
			},
			wantErr: true,
		},
	}

	parser := NewParser(authProvider)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(authProvider, tt.username)

			stmt, err := sqlparser.Parse(tt.query)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			err = parser.ValidatePermissions(stmt, tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckPermission(t *testing.T) {
	authProvider, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name               string
		username           string
		tableName          string
		requiredPermission permissions.PermissionType
		setup              func(auth.Provider, string)
		want               bool
		wantErr            bool
	}{
		{
			name:               "check permission with no permissions",
			username:           "test_user",
			tableName:          "users",
			requiredPermission: permissions.TablePermission,
			setup:              func(ap auth.Provider, username string) {},
			want:               false,
			wantErr:            false,
		},
		{
			name:               "check permission with table permission",
			username:           "test_user",
			tableName:          "users",
			requiredPermission: permissions.TablePermission,
			setup: func(ap auth.Provider, username string) {
				ap.AddUser(username, "test_token")
				ap.AddPermission(username, permissions.Permission{
					Type:   permissions.TablePermission,
					Action: permissions.Select,
					Table:  "users",
				})
			},
			want:    true,
			wantErr: false,
		},
		{
			name:               "check permission with invalid username",
			username:           "",
			tableName:          "users",
			requiredPermission: permissions.TablePermission,
			setup:              func(ap auth.Provider, username string) {},
			want:               false,
			wantErr:            true,
		},
	}

	parser := NewParser(authProvider)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(authProvider, tt.username)

			got, err := parser.CheckPermission(tt.username, tt.tableName, tt.requiredPermission)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPermission() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}
