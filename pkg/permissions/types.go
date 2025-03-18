package permissions

// PermissionType represents the type of permission
type PermissionType int

const (
	TablePermission PermissionType = iota
	ColumnPermission
	RowPermission
)

// Action represents the type of database action
type Action int

const (
	Select Action = iota
	Insert
	Update
	Delete
	Create
	Drop
	Alter
)

// Special permission markers
const (
	// RevokedPermissionPrefix is used to mark a permission as revoked
	RevokedPermissionPrefix = "REVOKED:"
	// WildcardPermission is used to represent a wildcard permission
	WildcardPermission = "*"
)

// Permission represents a parsed permission
type Permission struct {
	Type      PermissionType
	Table     string
	Column    string
	Condition string
	Action    Action
}

// RowPermissionRule represents a row-level permission rule
type RowPermissionRule struct {
	Granted bool
}
