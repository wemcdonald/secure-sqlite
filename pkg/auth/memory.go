package auth

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/wemcdonald/secure_sqlite/pkg/permissions"
)

// noRowsRow is a custom sql.Row that always returns sql.ErrNoRows
type noRowsRow struct {
	*sql.Row
}

func (r *noRowsRow) Scan(dest ...interface{}) error {
	return sql.ErrNoRows
}

// MemoryProvider implements AuthProvider for testing
type MemoryProvider struct {
	users       map[string]string                   // username -> token
	permissions map[string][]permissions.Permission // username -> []permissions
	roles       map[int64]string                    // roleID -> roleName
	roleNames   map[string]int64                    // roleName -> roleID
	userRoles   map[string][]string                 // username -> []roleName
	sessions    map[string]int64                    // sessionID -> userID
	nextRoleID  int64                               // auto-incrementing role ID
	mu          sync.RWMutex
	db          *sql.DB
}

// NewMemoryProvider creates a new memory auth provider
func NewMemoryProvider() *MemoryProvider {
	db, _ := sql.Open("sqlite3", ":memory:")
	return &MemoryProvider{
		users:       make(map[string]string),
		permissions: make(map[string][]permissions.Permission),
		roles:       make(map[int64]string),
		roleNames:   make(map[string]int64),
		userRoles:   make(map[string][]string),
		sessions:    make(map[string]int64),
		nextRoleID:  1,
		db:          db,
	}
}

// AddUser adds a test user to the memory provider
func (m *MemoryProvider) AddUser(username, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = token
}

// AddPermission adds a permission for a user
func (m *MemoryProvider) AddPermission(username string, permission permissions.Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.permissions[username] = append(m.permissions[username], permission)
}

// AddRole adds a role and returns its ID
func (m *MemoryProvider) AddRole(roleName string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role already exists
	if _, exists := m.roleNames[roleName]; exists {
		return 0, fmt.Errorf("role %s already exists", roleName)
	}

	// Create new role
	roleID := m.nextRoleID
	m.nextRoleID++
	m.roles[roleID] = roleName
	m.roleNames[roleName] = roleID

	return roleID, nil
}

// Authenticate implements AuthProvider.Authenticate
func (m *MemoryProvider) Authenticate(username, token string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.users[username] == token, nil
}

// GetUserPermissions implements AuthProvider.GetUserPermissions
func (m *MemoryProvider) GetUserPermissions(username string) ([]permissions.Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.users[username]; !ok {
		return nil, fmt.Errorf("user %s not found", username)
	}
	perms, ok := m.permissions[username]
	if !ok {
		return []permissions.Permission{}, nil
	}
	return perms, nil
}

// Query implements AuthProvider.Query
func (m *MemoryProvider) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, sql.ErrNoRows
}

// QueryRow implements AuthProvider.QueryRow
func (m *MemoryProvider) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

// UpdateUserPermissions implements AuthProvider.UpdateUserPermissions
func (m *MemoryProvider) UpdateUserPermissions(username string, permissions []permissions.Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.permissions[username] = permissions
	return nil
}

// GetUserID returns the numeric ID for a user
func (m *MemoryProvider) GetUserID(username string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.users[username]; !ok {
		return 0, fmt.Errorf("user %s not found", username)
	}

	// For the memory provider, we'll use a simple hash of the username as the ID
	var id int64
	for _, c := range username {
		id = id*31 + int64(c)
	}
	return id, nil
}

// GetUsersWithRole returns a list of usernames that have the given role
func (m *MemoryProvider) GetUsersWithRole(roleName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var users []string
	for username, roles := range m.userRoles {
		for _, role := range roles {
			if role == roleName {
				users = append(users, username)
				break
			}
		}
	}
	return users, nil
}

// GetRoleName returns the name of a role given its ID
func (m *MemoryProvider) GetRoleName(roleID int64) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roleName, ok := m.roles[roleID]
	if !ok {
		return "", fmt.Errorf("role with ID %d not found", roleID)
	}
	return roleName, nil
}

// StoreSession stores a session for a user
func (m *MemoryProvider) StoreSession(sessionID string, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = userID
	return nil
}

// ValidateSession checks if a session is valid
func (m *MemoryProvider) ValidateSession(sessionID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.sessions[sessionID]
	return ok, nil
}

// TerminateSession terminates a session
func (m *MemoryProvider) TerminateSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

// GetRoleID returns the ID of a role given its name
func (m *MemoryProvider) GetRoleID(roleName string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roleID, ok := m.roleNames[roleName]
	if !ok {
		return 0, fmt.Errorf("role %s not found", roleName)
	}
	return roleID, nil
}

// DeleteRole deletes a role
func (m *MemoryProvider) DeleteRole(roleID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	roleName, ok := m.roles[roleID]
	if !ok {
		return fmt.Errorf("role with ID %d not found", roleID)
	}

	// Delete role from maps
	delete(m.roles, roleID)
	delete(m.roleNames, roleName)

	// Remove role from all users
	for username, roles := range m.userRoles {
		newRoles := make([]string, 0, len(roles))
		for _, r := range roles {
			if r != roleName {
				newRoles = append(newRoles, r)
			}
		}
		m.userRoles[username] = newRoles
	}

	return nil
}
