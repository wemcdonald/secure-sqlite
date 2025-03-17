package auth

// Provider defines the interface for authentication
type Provider interface {
	// Authenticate verifies if the given username and token are valid
	Authenticate(username, token string) (bool, error)

	// GetUserPermissions returns the list of permissions for a user
	GetUserPermissions(username string) ([]string, error)
}

// MockProvider implements Provider for testing
type MockProvider struct {
	AuthenticateFunc func(username, token string) (bool, error)
	GetPermsFunc     func(username string) ([]string, error)
}

func (m *MockProvider) Authenticate(username, token string) (bool, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(username, token)
	}
	return true, nil
}

func (m *MockProvider) GetUserPermissions(username string) ([]string, error) {
	if m.GetPermsFunc != nil {
		return m.GetPermsFunc(username)
	}
	return []string{"*"}, nil
}
