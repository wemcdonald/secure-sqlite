package auth

import (
	"errors"
	"sync"
)

// MemoryAuthProvider implements AuthProvider interface using in-memory storage
type MemoryAuthProvider struct {
	users       map[string]string   // username -> password hash
	permissions map[string][]string // username -> permissions
	mu          sync.RWMutex
}

// NewMemoryAuthProvider creates a new in-memory authentication provider
func NewMemoryAuthProvider() *MemoryAuthProvider {
	return &MemoryAuthProvider{
		users:       make(map[string]string),
		permissions: make(map[string][]string),
	}
}

// AddUser adds a new user with their password and permissions
func (m *MemoryAuthProvider) AddUser(username, password string, permissions []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// In a real implementation, you would hash the password
	m.users[username] = password
	m.permissions[username] = permissions
}

// Authenticate checks if the username and password are valid
func (m *MemoryAuthProvider) Authenticate(username, password string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storedPassword, exists := m.users[username]
	if !exists {
		return false, errors.New("user not found")
	}

	// In a real implementation, you would compare hashed passwords
	return storedPassword == password, nil
}

// GetUserPermissions returns the permissions for a given user
func (m *MemoryAuthProvider) GetUserPermissions(username string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	permissions, exists := m.permissions[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	return permissions, nil
}
