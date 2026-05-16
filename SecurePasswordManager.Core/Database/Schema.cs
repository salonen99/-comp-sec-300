/*
 * Database Schema Definition
 * 
 * SECURITY FEATURES:
 * - All sensitive data stored encrypted (BLOB fields)
 * - Schema versioning for safe migrations
 * - Minimal metadata exposure
 */

namespace SecurePasswordManager.Core.Database;

/// <summary>
/// Database schema definitions and SQL statements.
/// 
/// SECURITY NOTES:
/// - All SQL uses parameterized queries (defined in DbManager)
/// - Schema designed to minimize metadata leakage
/// - Encrypted fields stored as BLOB
/// </summary>
public static class Schema
{
    public const int CurrentVersion = 1;
    
    /// <summary>
    /// Create vault metadata table.
    /// Stores salt and verification hash for master password.
    /// Includes MFA settings for optional Multi-Factor Authentication.
    /// </summary>
    public const string CreateMetadataTable = """
        CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verification_hash BLOB NOT NULL,
            created_at TEXT NOT NULL,
            last_accessed_at TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            mfa_settings TEXT
        );
        """;
    
    /// <summary>
    /// Create password entries table.
    /// All sensitive fields are encrypted BLOBs.
    /// </summary>
    public const string CreateEntriesTable = """
        CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_service_name BLOB NOT NULL,
            encrypted_username BLOB NOT NULL,
            encrypted_password BLOB NOT NULL,
            encrypted_url BLOB,
            encrypted_notes BLOB,
            encrypted_category BLOB,
            created_at TEXT NOT NULL,
            modified_at TEXT NOT NULL,
            password_changed_at TEXT,
            is_favorite INTEGER NOT NULL DEFAULT 0
        );
        """;
    
    /// <summary>
    /// Create index for faster lookups.
    /// Note: Cannot index encrypted fields.
    /// </summary>
    public const string CreateIndexes = """
        CREATE INDEX IF NOT EXISTS idx_entries_favorite ON password_entries(is_favorite);
        CREATE INDEX IF NOT EXISTS idx_entries_modified ON password_entries(modified_at DESC);
        """;
    
    /// <summary>
    /// All schema creation statements in order.
    /// </summary>
    public static readonly string[] CreateStatements =
    [
        CreateMetadataTable,
        CreateEntriesTable,
        CreateIndexes
    ];
}
