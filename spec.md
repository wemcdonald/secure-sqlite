# SecureSQLite Library Specification

## Overview

SecureSQLite is a wrapper library for SQLite3 that implements Access Control Lists (ACLs) to provide authorization capabilities while maintaining full compatibility with the existing SQLite library for all non-authorization functionality.

## Design Goals

1. Provide fine-grained access control at table, view, and row levels
2. Fall back to existing SQLite library for non-auth functionality
3. Minimal performance overhead
4. Protection against authorization bypass
5. Support for role-based access control (RBAC)
6. Ability to audit access attempts

## Database Schema

SecureSQLite will use the following tables to implement the authorization system:

```sql
CREATE TABLE auth_users (
    user_id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    token_hash TEXT NOT NULL
);

CREATE TABLE auth_roles (
    role_id INTEGER PRIMARY KEY,
    role_name TEXT UNIQUE NOT NULL
);

CREATE TABLE auth_user_roles (
    user_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES auth_users(user_id),
    FOREIGN KEY (role_id) REFERENCES auth_roles(role_id)
);

CREATE TABLE auth_permissions (
    permission_id INTEGER PRIMARY KEY,
    permission_name TEXT UNIQUE NOT NULL
);

CREATE TABLE auth_role_permissions (
    role_id INTEGER,
    permission_id INTEGER,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES auth_roles(role_id),
    FOREIGN KEY (permission_id) REFERENCES auth_permissions(permission_id)
);

CREATE TABLE auth_object_permissions (
    permission_id INTEGER,
    object_name TEXT NOT NULL,
    PRIMARY KEY (permission_id, object_name),
    FOREIGN KEY (permission_id) REFERENCES auth_permissions(permission_id)
);
```

## Core Components

### 1. Connection Management

* **SecureConnection** - Wraps the SQLite connection and tracks the current user context
* **ConnectionPool** - Manages connection pooling with user context preservation

### 2. Authentication Layer

* **UserManager** - Handles user creation, token verification, and session management
* **TokenStorage** - Handles secure token validation (tokens are generated externally)

### 3. Authorization Layer

* **PermissionChecker** - Validates if a user has permission to perform an operation
* **SQLParser** - Uses a reliable third-party SQL parsing library (NOT regex-based)
* **QueryTransformer** - Modifies queries to enforce row-level security

### 4. Administration

* **RoleManager** - Handles role creation and assignment
* **PermissionManager** - Manages permission definitions and assignments
* **AuditLogger** - Records access attempts and permission changes

## Supported Permission Types

The library will support all standard database permission types:

1. **SELECT** - Ability to read data from tables or views
2. **INSERT** - Ability to add new records
3. **UPDATE** - Ability to modify existing records
4. **DELETE** - Ability to remove records
5. **TRUNCATE** - Ability to delete all records from a table
6. **REFERENCES** - Ability to create a foreign key constraint referencing a table
7. **TRIGGER** - Ability to create triggers on a table
8. **CREATE** - Ability to create new objects (tables, views, indices, etc.)
9. **ALTER** - Ability to modify the structure of database objects
10. **DROP** - Ability to delete database objects
11. **EXECUTE** - Ability to execute stored procedures or functions
12. **INDEX** - Ability to create indices on tables
13. **VACUUM** - Ability to rebuild the database
14. **PRAGMA** - Ability to change database settings
15. **ATTACH** - Ability to attach additional database files
16. **DETACH** - Ability to detach database files

These permissions can be applied at the database, table, view, and row levels.

## API Specification

### Initialization

```typescript
// Create a new secure database
function createSecureDatabase(path: string, options?: SecurityOptions): SecureDatabase;

// Open an existing secure database
function openSecureDatabase(path: string, options?: SecurityOptions): SecureDatabase;

// Security options interface
interface SecurityOptions {
  auditLogging?: boolean;
  parserOptions?: object; // Options for the SQL parsing library
  sessionTimeoutMinutes?: number;
}
```

### User Management

```typescript
// Create a new user
function createUser(username: string, token: string): UserID;

// Authenticate and create a session
function login(username: string, token: string): SessionToken;

// End a session
function logout(sessionToken: SessionToken): void;

// Delete a user
function deleteUser(userId: UserID): void;

// Update a user's token
function updateUserToken(userId: UserID, newToken: string): void;
```

### Role Management

```typescript
// Create a new role
function createRole(roleName: string): RoleID;

// Assign a role to a user
function assignRoleToUser(userId: UserID, roleId: RoleID): void;

// Remove a role from a user
function removeRoleFromUser(userId: UserID, roleId: RoleID): void;
```

### Permission Management

```typescript
// Define a new permission
function createPermission(permissionName: string): PermissionID;

// Assign a permission to a role
function assignPermissionToRole(roleId: RoleID, permissionId: PermissionID): void;

// Grant permission to a database object
function grantObjectPermission(
  permissionId: PermissionID, 
  objectName: string, 
  objectType: 'table' | 'view' | 'function' | 'trigger' | 'index'
): void;

// Grant row-level permission
function grantRowPermission(
  permissionId: PermissionID,
  tableName: string,
  condition: string
): void;
```

### Query Execution

```typescript
// Execute a query with the current user context
function executeQuery(
  sessionToken: SessionToken, 
  sqlQuery: string, 
  parameters?: any[]
): QueryResult;

// Execute a prepared statement
function executePreparedStatement(
  sessionToken: SessionToken,
  statementId: StatementID,
  parameters?: any[]
): QueryResult;

// Prepare a statement for repeated execution
function prepareStatement(
  sessionToken: SessionToken,
  sqlQuery: string
): StatementID;
```

### Transaction Management

```typescript
// Begin a transaction with the current user context
function beginTransaction(sessionToken: SessionToken): TransactionID;

// Commit a transaction
function commitTransaction(transactionId: TransactionID): void;

// Rollback a transaction
function rollbackTransaction(transactionId: TransactionID): void;
```

### SQLite Native API Passthrough

```typescript
// Access the underlying SQLite instance (without auth checks)
// Only available to admin users
function getUnderlyingSQLiteHandle(sessionToken: SessionToken): SQLiteHandle;

// Check if a method requires authorization
function requiresAuthorization(methodName: string): boolean;
```

## SQL Parsing Strategy

1. Use a reliable third-party SQL parsing library (NO regex)
2. Recommended options:
   - SQLite official parser bindings
   - node-sqlite-parser
   - sql-parser-cst
3. Cache parsing results for repeated queries

## Security Features

### Authorization Enforcement

The library should enforce authorization at these levels:

1. **Statement Level**: Prevent execution of unauthorized statement types
2. **Object Level**: Restrict access to tables, views, and other objects
3. **Row Level**: Filter rows based on permissions
4. **Column Level**: Exclude or mask sensitive columns

### Auditing Capabilities

* Log all permission checks (success/failure)
* Log all schema changes to permission tables
* Log all authentication attempts
* Support for exporting audit logs

## Error Handling

The library should provide clear error messages for:

* Authentication failures
* Authorization failures
* SQL parsing errors
* Database connection errors

All errors should be categorized by type with unique error codes.

## Implementation Guidelines

### Performance Considerations

1. Cache permission results where appropriate
2. Use prepared statements for repeated queries
3. Implement connection pooling with user context
4. Minimize transaction overhead for permission checks

### Row-Level Security Implementation

Use one of these approaches:

1. **View-based**: Create secure views that include permission filters
2. **Query modification**: Append WHERE clauses to enforce permissions
3. **Triggers**: Use triggers to validate permissions on write operations

## Testing Requirements

The library implementation should include comprehensive tests for:

1. **Authentication Module**
   - Token validation
   - Session management
   - User creation and management

2. **Authorization Module**
   - Permission enforcement for all supported permission types
   - Role-based access control
   - Object-level permissions
   - Row-level security

3. **SQL Parser Integration**
   - Correct identification of SQL operations
   - Proper handling of complex queries
   - Statement transformation

4. **Audit Logging**
   - Verification of log entries
   - Log integrity
   - Log retrieval

5. **Error Handling**
   - Proper error reporting
   - Appropriate HTTP status codes
   - Informative error messages

6. **Performance Tests**
   - Overhead measurement
   - Caching effectiveness
   - Connection pooling efficiency

The test suite should NOT duplicate tests for existing SQLite functionality unless that functionality is directly modified by the SecureSQLite implementation.

## Example Usage

```typescript
// Initialize the database
const secureDb = createSecureDatabase('myapp.db', {
  auditLogging: true,
  parserOptions: {
    dialect: 'sqlite'
  }
});

// Create users and roles
const adminId = secureDb.createUser('admin', 'admin-token-123');
const userId = secureDb.createUser('regularUser', 'user-token-456');

const adminRoleId = secureDb.createRole('admin');
const userRoleId = secureDb.createRole('user');

secureDb.assignRoleToUser(adminId, adminRoleId);
secureDb.assignRoleToUser(userId, userRoleId);

// Define permissions
const selectAllId = secureDb.createPermission('SELECT');
const updateAllId = secureDb.createPermission('UPDATE');
const selectOwnId = secureDb.createPermission('SELECT_OWN');

// Assign permissions to roles
secureDb.assignPermissionToRole(adminRoleId, selectAllId);
secureDb.assignPermissionToRole(adminRoleId, updateAllId);
secureDb.assignPermissionToRole(userRoleId, selectOwnId);

// Grant object permissions
secureDb.grantObjectPermission(selectAllId, 'employees', 'table');
secureDb.grantObjectPermission(updateAllId, 'employees', 'table');
secureDb.grantRowPermission(selectOwnId, 'employees', 'user_id = current_user_id()');

// User login
const adminSession = secureDb.login('admin', 'admin-token-123');
const userSession = secureDb.login('regularUser', 'user-token-456');

// Execute queries with different permissions
const allEmployees = secureDb.executeQuery(
  adminSession, 
  'SELECT * FROM employees'
);

const ownEmployeeRecords = secureDb.executeQuery(
  userSession,
  'SELECT * FROM employees'
); // Will be filtered to only show own records
```

## Deployment Considerations

1. Provide migration tools for existing SQLite databases
2. Document backup and recovery procedures
3. Provide guidelines for secure configuration
4. Support both synchronous and asynchronous APIs
