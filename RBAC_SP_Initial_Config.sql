/*******************************************************************************
 * RBAC STORED PROCEDURE: Initial Configuration
 * 
 * Purpose: One-time setup of account-level RBAC framework including:
 *   - Account settings (SECONDARY_ROLES)
 *   - SRS_* System Roles (account administration)
 *   - SRF_* Functional Roles (capability - what you can do)
 *   - Account-level privilege grants
 *   - Role hierarchy relationships
 *   - ADMIN database with RBAC, DEVOPS, CLONES, SECURITY, GOVERNANCE, BACKUP, HADR schemas
 *   - Validation and verification of all created objects
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Deployment Role: ACCOUNTADMIN (required for initial setup)
 * 
 *   Creates:
 *     - ADMIN database with schemas (RBAC, DEVOPS, CLONES, SECURITY, GOVERNANCE, BACKUP, HADR)
 *     - System Roles (SRS_*)
 *     - Functional Roles (SRF_*)
 *     - Role hierarchy and privileges
 * 
 *   Dependencies:    
 *     - Must be run first before any other RBAC scripts
 *     - ACCOUNTADMIN access required
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SECTIONS:
 * ─────────────────────────────────────────────────────────────────────────────
 *   1.  Account Settings (SECONDARY_ROLES)
 *   2.  System Roles (SRS_*)
 *   3.  System Role Hierarchy
 *   4.  System Role Privileges
 *   5.  Functional Roles (SRF_*) per Environment
 *   6.  Functional Role Account-Level Privileges
 *   7.  SRS_DEVOPS Configuration
 *   8.  ADMIN Database and Schemas
 *   9.  ADMIN Schema Privileges
 *   10. Environment-Specific ADMIN Access
 *   11. Validation and Verification
 * 
 * ADMIN DATABASE STRUCTURE:
 * ─────────────────────────────────────────────────────────────────────────────
 *   ADMIN.RBAC       - Core RBAC procedures (Help, Config, Users, Roles, Audit)
 *   ADMIN.DEVOPS     - DevOps procedures (Pipelines, Deployments, Git, Monitoring)
 *   ADMIN.CLONES     - Clone procedures (Management, Audit, Compliance, Monitoring)
 *   ADMIN.SECURITY   - Security procedures (Alerts, Exceptions, Anomaly Detection)
 *   ADMIN.GOVERNANCE - Data Governance (RLS, Masking, Classification, Tagging)
 *   ADMIN.BACKUP     - Backup Management (Create, Restore, Policies, Retention)
 *   ADMIN.HADR       - HA/DR (Replication, Failover, DR Testing, RTO/RPO)
 * 
 * OWNERSHIP:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Database/Schemas owned by: SRS_SYSTEM_ADMIN
 *   
 * ACCESS MATRIX:
 * ─────────────────────────────────────────────────────────────────────────────
 *   | Schema     | PUBLIC | SRS_DEVOPS | SRS_SECURITY | SRF_*_DEVELOPER | SRF_*_DBADMIN |
 *   |------------|--------|------------|--------------|-----------------|---------------|
 *   | RBAC       | USAGE  | USAGE      | ALL          | USAGE           | USAGE         |
 *   | DEVOPS     | -      | ALL        | USAGE        | -               | USAGE         |
 *   | CLONES     | USAGE  | USAGE      | ALL          | USAGE           | USAGE         |
 *   | SECURITY   | -      | -          | ALL          | -               | USAGE         |
 *   | GOVERNANCE | -      | -          | ALL          | -               | USAGE         |
 *   | BACKUP     | -      | -          | ALL          | -               | USAGE         |
 *   | HADR       | -      | -          | ALL          | -               | USAGE (view)  |
 * 
 * VALIDATION (Section 11):
 * ─────────────────────────────────────────────────────────────────────────────
 *   After execution, validates:
 *   - ADMIN database exists and ownership
 *   - All schemas exist (RBAC, DEVOPS, CLONES, SECURITY)
 *   - System roles exist (SRS_*)
 *   - Functional roles exist per environment (SRF_*)
 *   - Key grants are in place
 *   - Role hierarchy is configured
 * 
 * This procedure is IDEMPOTENT - safe to re-run without side effects.
 * 
 * Parameters:
 *   P_ENVIRONMENTS - Array of environments to create (default: all)
 *                    Example: ARRAY_CONSTRUCT('DEV', 'TST', 'PRD')
 *   P_DRY_RUN      - If TRUE, shows what would be created without executing
 * 
 * Execution Role: ACCOUNTADMIN or SECURITYADMIN
 * 
 * Usage Examples:
 *   -- Full setup (all environments)
 *   CALL RBAC_INITIAL_CONFIG(NULL, FALSE);
 *   
 *   -- Setup specific environments only
 *   CALL RBAC_INITIAL_CONFIG(ARRAY_CONSTRUCT('DEV', 'PRD'), FALSE);
 *   
 *   -- Dry run to preview changes
 *   CALL RBAC_INITIAL_CONFIG(NULL, TRUE);
 *   
 *   -- Validate configuration anytime
 *   CALL RBAC_VALIDATE_CONFIG();
 ******************************************************************************/


 CALL RBAC_INITIAL_CONFIG(NULL, FALSE);


CREATE OR REPLACE SECURE PROCEDURE RBAC_INITIAL_CONFIG(
    P_ENVIRONMENTS ARRAY DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_environments ARRAY;
    v_env VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_errors ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
    v_functional_roles ARRAY := ARRAY_CONSTRUCT('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN');
    v_system_roles ARRAY;
    v_role_obj OBJECT;
    v_role_hierarchy ARRAY;
    v_grant OBJECT;
    v_system_privileges ARRAY;
    v_priv OBJECT;
    v_role_level VARCHAR;
    v_role_name VARCHAR;
    v_account_privileges ARRAY;
    v_schemas ARRAY;
    v_schema_name VARCHAR;
    v_schema_privileges ARRAY;
    v_env_grants ARRAY;
    v_validation OBJECT;
    v_system_grants ARRAY;
    i INTEGER;
    j INTEGER;
    env_idx INTEGER;
    role_idx INTEGER;
    v_comment VARCHAR;
    v_hierarchy ARRAY;
    v_privileges ARRAY;
    v_hierarchy_grants ARRAY;
    grant_idx INTEGER;
    v_dbadmin_role VARCHAR;
    v_dbadmin_privileges ARRAY;
    priv_idx INTEGER;
    v_admin_grants ARRAY;
    v_env_admin_grants ARRAY;
    v_validation_results ARRAY;
    v_validation_errors ARRAY;
    v_db_exists BOOLEAN;
    v_schema_count INTEGER;
    v_role_count INTEGER;
    v_grant_count INTEGER;
    v_env_role_count INTEGER;
    v_owner VARCHAR;
    v_hierarchy_count INTEGER;
    val_idx INTEGER;
    v_final_status VARCHAR;
BEGIN
    -- Default to all environments if not specified
    IF (P_ENVIRONMENTS IS NULL) THEN
        v_environments := ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PPE', 'PRD');
    ELSE
        v_environments := P_ENVIRONMENTS;
    END IF;
    
    -- Validate environments
    FOR i IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        IF (v_environments[i] NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Invalid environment: ' || v_environments[i]::VARCHAR || '. Must be one of: DEV, TST, UAT, PPE, PRD'
            );
        END IF;
    END FOR;

    -- =========================================================================
    -- SECTION 1: ACCOUNT SETTINGS
    -- =========================================================================
    -- Note: DEFAULT_SECONDARY_ROLES is a USER-level parameter, not ACCOUNT-level
    -- Users can enable it individually via: ALTER USER <name> SET DEFAULT_SECONDARY_ROLES = ('ALL')
    -- Skipping account-level configuration as it's not supported
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ACCOUNT_SETTINGS',
        'action', 'Skip SECONDARY_ROLES (user-level setting)',
        'sql', '-- DEFAULT_SECONDARY_ROLES is set per user, not at account level'
    ));

    -- =========================================================================
    -- SECTION 2: SYSTEM ROLES (SRS)
    -- =========================================================================
    v_system_roles := ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('name', 'SRS_ACCOUNT_ADMIN', 'comment', 'System role for account-level administration'),
        OBJECT_CONSTRUCT('name', 'SRS_SECURITY_ADMIN', 'comment', 'System role for security and access management'),
        OBJECT_CONSTRUCT('name', 'SRS_USER_ADMIN', 'comment', 'System role for user management'),
        OBJECT_CONSTRUCT('name', 'SRS_SYSTEM_ADMIN', 'comment', 'System role for system administration'),
        OBJECT_CONSTRUCT('name', 'SRS_DEVOPS', 'comment', 'System role for DevOps CI/CD operations - owns objects in TST/UAT/PPE/PRD')
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_roles) - 1 DO
        v_role_obj := v_system_roles[i];
        v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_obj:name::VARCHAR || 
                 ' COMMENT = ''' || v_role_obj:comment::VARCHAR || '''';
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'SYSTEM_ROLES',
            'action', 'Create ' || v_role_obj:name::VARCHAR,
            'sql', v_sql
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- =========================================================================
    -- SECTION 3: SYSTEM ROLE HIERARCHY
    -- =========================================================================
    v_system_grants := ARRAY_CONSTRUCT(
        'GRANT ROLE SRS_ACCOUNT_ADMIN TO ROLE ACCOUNTADMIN',
        'GRANT ROLE SRS_SECURITY_ADMIN TO ROLE SECURITYADMIN',
        'GRANT ROLE SRS_USER_ADMIN TO ROLE USERADMIN',
        'GRANT ROLE SRS_SYSTEM_ADMIN TO ROLE SYSADMIN',
        'GRANT ROLE SRS_DEVOPS TO ROLE SYSADMIN',
        'GRANT ROLE SRS_SECURITY_ADMIN TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT ROLE SRS_USER_ADMIN TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ROLE SRS_SYSTEM_ADMIN TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT ROLE SRS_DEVOPS TO ROLE SRS_SYSTEM_ADMIN'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_grants) - 1 DO
        v_sql := v_system_grants[i];
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'SYSTEM_ROLE_HIERARCHY',
            'sql', v_sql
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- =========================================================================
    -- SECTION 4: SYSTEM ROLE PRIVILEGES
    -- =========================================================================
    v_system_privileges := ARRAY_CONSTRUCT(
        'GRANT CREATE ROLE ON ACCOUNT TO ROLE SRS_SECURITY_ADMIN',
        'GRANT MANAGE GRANTS ON ACCOUNT TO ROLE SRS_SECURITY_ADMIN',
        'GRANT CREATE USER ON ACCOUNT TO ROLE SRS_USER_ADMIN',
        'GRANT MANAGE ACCOUNT SUPPORT CASES ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT MONITOR USAGE ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT MONITOR SECURITY ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT IMPORT SHARE ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT CREATE SHARE ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT OVERRIDE SHARE RESTRICTIONS ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT CREATE DATA EXCHANGE LISTING ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_privileges) - 1 DO
        v_sql := v_system_privileges[i];
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'SYSTEM_ROLE_PRIVILEGES',
            'sql', v_sql
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- =========================================================================
    -- SECTION 5: FUNCTIONAL ROLES (SRF) PER ENVIRONMENT
    -- =========================================================================
    FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        v_env := v_environments[env_idx];
        
        -- Create functional roles for this environment
        FOR role_idx IN 0 TO ARRAY_SIZE(v_functional_roles) - 1 DO
            v_role_level := v_functional_roles[role_idx];
            v_role_name := 'SRF_' || v_env || '_' || v_role_level;
            
            -- Set appropriate comment based on environment and role
            IF (v_role_level IN ('DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST') AND (NOT (v_env = 'DEV'))) THEN
                v_comment := v_env || ': ' || v_role_level || ' - read-only capability (requires SRA_* for data access)';
            ELSE
                v_comment := v_env || ': ' || v_role_level || ' - capability role (requires SRA_* for data access)';
            END IF;
            
            v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_name || ' COMMENT = ''' || v_comment || '''';
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'section', 'FUNCTIONAL_ROLES',
                'environment', v_env,
                'role', v_role_name,
                'sql', v_sql
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
        
        -- Create functional role hierarchy for this environment
        v_hierarchy_grants := ARRAY_CONSTRUCT(
            'GRANT ROLE SRF_' || v_env || '_END_USER TO ROLE SRF_' || v_env || '_ANALYST',
            'GRANT ROLE SRF_' || v_env || '_ANALYST TO ROLE SRF_' || v_env || '_DEVELOPER',
            'GRANT ROLE SRF_' || v_env || '_DEVELOPER TO ROLE SRF_' || v_env || '_TEAM_LEADER',
            'GRANT ROLE SRF_' || v_env || '_TEAM_LEADER TO ROLE SRF_' || v_env || '_DATA_SCIENTIST',
            'GRANT ROLE SRF_' || v_env || '_DATA_SCIENTIST TO ROLE SRF_' || v_env || '_DBADMIN',
            'GRANT ROLE SRF_' || v_env || '_DBADMIN TO ROLE SRS_SYSTEM_ADMIN'
        );
        
        FOR grant_idx IN 0 TO ARRAY_SIZE(v_hierarchy_grants) - 1 DO
            v_sql := v_hierarchy_grants[grant_idx];
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'section', 'FUNCTIONAL_ROLE_HIERARCHY',
                'environment', v_env,
                'sql', v_sql
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
    END FOR;

    -- =========================================================================
    -- SECTION 6: FUNCTIONAL ROLE ACCOUNT-LEVEL PRIVILEGES
    -- =========================================================================
    FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        v_env := v_environments[env_idx];
        v_dbadmin_role := 'SRF_' || v_env || '_DBADMIN';
        
        v_dbadmin_privileges := ARRAY_CONSTRUCT(
            'GRANT CREATE DATABASE ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT CREATE WAREHOUSE ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            -- Note: APPLY ROW ACCESS POLICY ON ACCOUNT is not supported - grant at schema level instead
            'GRANT APPLY TAG ON ACCOUNT TO ROLE ' || v_dbadmin_role
        );
        
        FOR priv_idx IN 0 TO ARRAY_SIZE(v_dbadmin_privileges) - 1 DO
            v_sql := v_dbadmin_privileges[priv_idx];
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'section', 'DBADMIN_PRIVILEGES',
                'environment', v_env,
                'sql', v_sql
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
    END FOR;

    -- =========================================================================
    -- SECTION 7: SRS_DEVOPS CONFIGURATION
    -- =========================================================================
    -- Grant DEV END_USER to DEVOPS for CI/CD metadata access
    IF (ARRAY_CONTAINS('DEV'::VARIANT, v_environments)) THEN
        v_sql := 'GRANT ROLE SRF_DEV_END_USER TO ROLE SRS_DEVOPS';
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'DEVOPS_CONFIG',
            'action', 'Grant DEV read access to DEVOPS',
            'sql', v_sql
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END IF;

    -- =========================================================================
    -- SECTION 8: ADMIN DATABASE AND SCHEMAS
    -- =========================================================================
    -- Create ADMIN database owned by SRS_SYSTEM_ADMIN for RBAC framework objects
    
    -- 8.1 Create ADMIN database
    v_sql := 'CREATE DATABASE IF NOT EXISTS ADMIN COMMENT = ''RBAC Framework Administration Database - Contains all RBAC procedures and configuration''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_DATABASE',
        'action', 'Create ADMIN database',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.2 Transfer ownership of ADMIN database to SRS_SYSTEM_ADMIN
    v_sql := 'GRANT OWNERSHIP ON DATABASE ADMIN TO ROLE SRS_SYSTEM_ADMIN COPY CURRENT GRANTS';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_DATABASE',
        'action', 'Transfer ADMIN ownership to SRS_SYSTEM_ADMIN',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.3 Create RBAC schema (core procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.RBAC COMMENT = ''Core RBAC procedures: Initial Config, User Management, Access/Service Roles, Audit, Help''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.RBAC schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.4 Create DEVOPS schema (CI/CD procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.DEVOPS COMMENT = ''DevOps procedures: CI/CD Pipelines, Deployments, Git Integration, Monitoring''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.DEVOPS schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.5 Create CLONES schema (clone management procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.CLONES COMMENT = ''Clone Management procedures: Clone Creation, Audit, Compliance, Monitoring''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.CLONES schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.6 Create SECURITY schema (security monitoring procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.SECURITY COMMENT = ''Security Monitoring procedures: Alerts, Exceptions, Anomaly Detection, Compliance''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.SECURITY schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.7 Create GOVERNANCE schema (data governance procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.GOVERNANCE COMMENT = ''Data Governance procedures: Row-Level Security, Masking, Classification, Tagging''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.GOVERNANCE schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.8 Create BACKUP schema (backup management procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.BACKUP COMMENT = ''Backup Management procedures: Create, Restore, Policies, Retention, Monitoring''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.BACKUP schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- 8.9 Create HADR schema (high availability / disaster recovery procedures)
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ADMIN.HADR COMMENT = ''HA/DR procedures: Replication, Failover, Failback, DR Testing, RTO/RPO Monitoring''';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'section', 'ADMIN_SCHEMAS',
        'action', 'Create ADMIN.HADR schema',
        'sql', v_sql
    ));
    
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION
            WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;
    
    -- =========================================================================
    -- SECTION 9: ADMIN SCHEMA PRIVILEGES
    -- =========================================================================
    -- Grant privileges on ADMIN database and schemas to appropriate roles
    
    v_admin_grants := ARRAY_CONSTRUCT(
        -- Database-level grants
        'GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_USER_ADMIN',
        'GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_DEVOPS',
        'GRANT USAGE ON DATABASE ADMIN TO ROLE PUBLIC',
        
        -- RBAC schema - core procedures (available to all)
        'GRANT USAGE ON SCHEMA ADMIN.RBAC TO ROLE PUBLIC',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE PUBLIC',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE PUBLIC',
        
        -- RBAC schema - admin procedures
        'GRANT ALL ON SCHEMA ADMIN.RBAC TO ROLE SRS_SECURITY_ADMIN',
        'GRANT CREATE PROCEDURE ON SCHEMA ADMIN.RBAC TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT CREATE TABLE ON SCHEMA ADMIN.RBAC TO ROLE SRS_SYSTEM_ADMIN',
        
        -- DEVOPS schema - DevOps procedures
        'GRANT USAGE ON SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT ALL ON SCHEMA ADMIN.DEVOPS TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON ALL TABLES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT SELECT ON FUTURE TABLES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT INSERT, UPDATE ON ALL TABLES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        'GRANT INSERT, UPDATE ON FUTURE TABLES IN SCHEMA ADMIN.DEVOPS TO ROLE SRS_DEVOPS',
        
        -- CLONES schema - Clone procedures (developers can use)
        'GRANT USAGE ON SCHEMA ADMIN.CLONES TO ROLE PUBLIC',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.CLONES TO ROLE PUBLIC',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.CLONES TO ROLE PUBLIC',
        'GRANT ALL ON SCHEMA ADMIN.CLONES TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON ALL TABLES IN SCHEMA ADMIN.CLONES TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT ON FUTURE TABLES IN SCHEMA ADMIN.CLONES TO ROLE SRS_SECURITY_ADMIN',
        
        -- SECURITY schema - Security monitoring (security admin only)
        'GRANT USAGE ON SCHEMA ADMIN.SECURITY TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.SECURITY TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.SECURITY TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.SECURITY TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ADMIN.SECURITY TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE ON FUTURE TABLES IN SCHEMA ADMIN.SECURITY TO ROLE SRS_SECURITY_ADMIN',
        
        -- GOVERNANCE schema - Data governance (security admin manages, DBAdmins can view/apply)
        'GRANT USAGE ON SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE TABLES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON ALL TABLES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON FUTURE TABLES IN SCHEMA ADMIN.GOVERNANCE TO ROLE SRS_SYSTEM_ADMIN',
        
        -- BACKUP schema - Backup management (security admin manages, DBAdmins can use)
        'GRANT USAGE ON SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE TABLES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT, INSERT ON FUTURE TABLES IN SCHEMA ADMIN.BACKUP TO ROLE SRS_SYSTEM_ADMIN',
        
        -- HADR schema - HA/DR management (security admin only, DBAdmins can view)
        'GRANT USAGE ON SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ALL ON SCHEMA ADMIN.HADR TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE TABLES IN SCHEMA ADMIN.HADR TO ROLE SRS_SECURITY_ADMIN',
        'GRANT USAGE ON SCHEMA ADMIN.HADR TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON ALL TABLES IN SCHEMA ADMIN.HADR TO ROLE SRS_SYSTEM_ADMIN',
        'GRANT SELECT ON FUTURE TABLES IN SCHEMA ADMIN.HADR TO ROLE SRS_SYSTEM_ADMIN'
    );
    
    FOR grant_idx IN 0 TO ARRAY_SIZE(v_admin_grants) - 1 DO
        v_sql := v_admin_grants[grant_idx];
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'ADMIN_SCHEMA_PRIVILEGES',
            'sql', v_sql
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;
    
    -- =========================================================================
    -- SECTION 10: ENVIRONMENT-SPECIFIC ADMIN ACCESS
    -- =========================================================================
    -- Grant appropriate ADMIN schema access to functional roles
    FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        v_env := v_environments[env_idx];
        
        v_env_admin_grants := ARRAY_CONSTRUCT(
            -- All functional roles can use RBAC procedures
            'GRANT USAGE ON DATABASE ADMIN TO ROLE SRF_' || v_env || '_END_USER',
            'GRANT USAGE ON SCHEMA ADMIN.RBAC TO ROLE SRF_' || v_env || '_END_USER',
            
            -- Developers can use Clone procedures
            'GRANT USAGE ON SCHEMA ADMIN.CLONES TO ROLE SRF_' || v_env || '_DEVELOPER',
            
            -- Team Leaders can view DevOps dashboards
            'GRANT USAGE ON SCHEMA ADMIN.DEVOPS TO ROLE SRF_' || v_env || '_TEAM_LEADER',
            
            -- DBAdmins can view Security, Governance, Backup, and HADR dashboards
            'GRANT USAGE ON SCHEMA ADMIN.SECURITY TO ROLE SRF_' || v_env || '_DBADMIN',
            'GRANT USAGE ON SCHEMA ADMIN.GOVERNANCE TO ROLE SRF_' || v_env || '_DBADMIN',
            'GRANT USAGE ON SCHEMA ADMIN.BACKUP TO ROLE SRF_' || v_env || '_DBADMIN',
            'GRANT USAGE ON SCHEMA ADMIN.HADR TO ROLE SRF_' || v_env || '_DBADMIN'
        );
        
        FOR grant_idx IN 0 TO ARRAY_SIZE(v_env_admin_grants) - 1 DO
            v_sql := v_env_admin_grants[grant_idx];
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'section', 'ENV_ADMIN_ACCESS',
                'environment', v_env,
                'sql', v_sql
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
    END FOR;

    -- =========================================================================
    -- SECTION 11: VALIDATION AND VERIFICATION
    -- =========================================================================
    -- Validate that all objects were created successfully
    
    IF (NOT P_DRY_RUN) THEN
        v_validation_results := ARRAY_CONSTRUCT();
        v_validation_errors := ARRAY_CONSTRUCT();
        v_db_exists := FALSE;
        v_schema_count := 0;
        v_role_count := 0;
        v_grant_count := 0;
        
        -- 11.1 Validate ADMIN database exists
        BEGIN
            SELECT TRUE INTO v_db_exists
            FROM INFORMATION_SCHEMA.DATABASES
            WHERE DATABASE_NAME = 'ADMIN';
            
            IF (v_db_exists) THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_DATABASE',
                    'status', 'PASS',
                    'message', 'ADMIN database exists'
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_DATABASE',
                    'status', 'FAIL',
                    'message', 'ADMIN database not found or not accessible',
                    'error', SQLERRM
                ));
        END;
        
        -- 11.2 Validate all schemas exist
        BEGIN
            SELECT COUNT(*) INTO v_schema_count
            FROM ADMIN.INFORMATION_SCHEMA.SCHEMATA
            WHERE SCHEMA_NAME IN ('RBAC', 'DEVOPS', 'CLONES', 'SECURITY');
            
            IF (v_schema_count = 4) THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_SCHEMAS',
                    'status', 'PASS',
                    'message', 'All 4 schemas exist (RBAC, DEVOPS, CLONES, SECURITY)',
                    'count', v_schema_count
                ));
            ELSE
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_SCHEMAS',
                    'status', 'PARTIAL',
                    'message', 'Expected 4 schemas, found ' || v_schema_count::VARCHAR,
                    'count', v_schema_count
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_SCHEMAS',
                    'status', 'FAIL',
                    'message', 'Could not verify schemas',
                    'error', SQLERRM
                ));
        END;
        
        -- 11.3 Validate system roles exist
        BEGIN
            SELECT COUNT(*) INTO v_role_count
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
            WHERE DELETED_ON IS NULL
              AND NAME IN ('SRS_ACCOUNT_ADMIN', 'SRS_SECURITY_ADMIN', 'SRS_USER_ADMIN', 'SRS_SYSTEM_ADMIN', 'SRS_DEVOPS');
            
            IF (v_role_count = 5) THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'SYSTEM_ROLES',
                    'status', 'PASS',
                    'message', 'All 5 system roles exist',
                    'count', v_role_count
                ));
            ELSE
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'SYSTEM_ROLES',
                    'status', 'PARTIAL',
                    'message', 'Expected 5 system roles, found ' || v_role_count::VARCHAR,
                    'count', v_role_count
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'SYSTEM_ROLES',
                    'status', 'FAIL',
                    'message', 'Could not verify system roles',
                    'error', SQLERRM
                ));
        END;
        
        -- 11.4 Validate functional roles exist for each environment
        FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
            v_env := v_environments[env_idx];
            v_env_role_count := 0;
            
            BEGIN
                SELECT COUNT(*) INTO v_env_role_count
                FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
                WHERE DELETED_ON IS NULL
                  AND NAME LIKE 'SRF_' || v_env || '_%';
                
                IF (v_env_role_count >= 6) THEN
                    v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                        'check', 'FUNCTIONAL_ROLES_' || v_env,
                        'status', 'PASS',
                        'message', v_env || ': ' || v_env_role_count::VARCHAR || ' functional roles exist',
                        'count', v_env_role_count
                    ));
                ELSE
                    v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                        'check', 'FUNCTIONAL_ROLES_' || v_env,
                        'status', 'PARTIAL',
                        'message', v_env || ': Expected 6+ functional roles, found ' || v_env_role_count::VARCHAR,
                        'count', v_env_role_count
                    ));
                END IF;
            EXCEPTION
                WHEN OTHER THEN
                    v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                        'check', 'FUNCTIONAL_ROLES_' || v_env,
                        'status', 'FAIL',
                        'message', 'Could not verify functional roles for ' || v_env,
                        'error', SQLERRM
                    ));
            END;
        END FOR;
        
        -- 11.5 Validate database ownership
        BEGIN
            v_owner := '';
            SELECT CATALOG_OWNER INTO v_owner
            FROM ADMIN.INFORMATION_SCHEMA.DATABASES
            WHERE DATABASE_NAME = 'ADMIN';
            
            IF (v_owner = 'SRS_SYSTEM_ADMIN') THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_OWNERSHIP',
                    'status', 'PASS',
                    'message', 'ADMIN database owned by SRS_SYSTEM_ADMIN',
                    'owner', v_owner
                ));
            ELSE
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_OWNERSHIP',
                    'status', 'WARNING',
                    'message', 'ADMIN database owned by ' || v_owner || ' (expected SRS_SYSTEM_ADMIN)',
                    'owner', v_owner
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ADMIN_OWNERSHIP',
                    'status', 'FAIL',
                    'message', 'Could not verify ADMIN ownership',
                    'error', SQLERRM
                ));
        END;
        
        -- 11.6 Validate key grants exist
        BEGIN
            SELECT COUNT(*) INTO v_grant_count
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
            WHERE DELETED_ON IS NULL
              AND GRANTEE_NAME IN ('SRS_SYSTEM_ADMIN', 'SRS_SECURITY_ADMIN', 'SRS_DEVOPS', 'PUBLIC')
              AND NAME = 'ADMIN'
              AND PRIVILEGE = 'USAGE';
            
            IF (v_grant_count >= 3) THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'DATABASE_GRANTS',
                    'status', 'PASS',
                    'message', 'ADMIN database grants configured',
                    'count', v_grant_count
                ));
            ELSE
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'DATABASE_GRANTS',
                    'status', 'WARNING',
                    'message', 'Some database grants may be missing',
                    'count', v_grant_count
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'DATABASE_GRANTS',
                    'status', 'FAIL',
                    'message', 'Could not verify grants',
                    'error', SQLERRM
                ));
        END;
        
        -- 11.7 Validate role hierarchy
        BEGIN
            v_hierarchy_count := 0;
            SELECT COUNT(*) INTO v_hierarchy_count
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
            WHERE DELETED_ON IS NULL
              AND GRANTED_ON = 'ROLE'
              AND GRANTEE_NAME LIKE 'SR%'
              AND NAME LIKE 'SR%';
            
            IF (v_hierarchy_count >= 10) THEN
                v_validation_results := ARRAY_APPEND(v_validation_results, OBJECT_CONSTRUCT(
                    'check', 'ROLE_HIERARCHY',
                    'status', 'PASS',
                    'message', 'Role hierarchy configured with ' || v_hierarchy_count::VARCHAR || ' grants',
                    'count', v_hierarchy_count
                ));
            ELSE
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ROLE_HIERARCHY',
                    'status', 'WARNING',
                    'message', 'Role hierarchy may be incomplete (' || v_hierarchy_count::VARCHAR || ' grants)',
                    'count', v_hierarchy_count
                ));
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_validation_errors := ARRAY_APPEND(v_validation_errors, OBJECT_CONSTRUCT(
                    'check', 'ROLE_HIERARCHY',
                    'status', 'FAIL',
                    'message', 'Could not verify role hierarchy',
                    'error', SQLERRM
                ));
        END;
        
        -- Append validation results to actions
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'section', 'VALIDATION',
            'validation_passed', ARRAY_SIZE(v_validation_results),
            'validation_issues', ARRAY_SIZE(v_validation_errors),
            'results', v_validation_results,
            'issues', v_validation_errors
        ));
        
        -- Add validation errors to main errors array
        FOR val_idx IN 0 TO ARRAY_SIZE(v_validation_errors) - 1 DO
            IF (v_validation_errors[val_idx]:status = 'FAIL') THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT(
                    'type', 'VALIDATION',
                    'check', v_validation_errors[val_idx]:check,
                    'error', v_validation_errors[val_idx]:message
                ));
            END IF;
        END FOR;
    END IF;

    -- =========================================================================
    -- Return Results
    -- =========================================================================
    v_final_status := 'SUCCESS';
    IF (ARRAY_SIZE(v_errors) > 0) THEN
        v_final_status := 'PARTIAL_SUCCESS';
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_final_status,
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'environments_configured', v_environments,
        'summary', OBJECT_CONSTRUCT(
            'actions_executed', ARRAY_SIZE(v_actions),
            'errors_encountered', ARRAY_SIZE(v_errors),
            'admin_database', 'ADMIN',
            'schemas_created', ARRAY_CONSTRUCT('RBAC', 'DEVOPS', 'CLONES', 'SECURITY')
        ),
        'actions', v_actions,
        'errors', v_errors,
        'next_steps', ARRAY_CONSTRUCT(
            '1. Deploy RBAC procedures to ADMIN.RBAC schema',
            '2. Deploy DevOps procedures to ADMIN.DEVOPS schema',
            '3. Deploy Clone procedures to ADMIN.CLONES schema',
            '4. Deploy Security procedures to ADMIN.SECURITY schema',
            '5. Run ADMIN.RBAC.RBAC_CREATE_WAREHOUSE() for each environment',
            '6. Run ADMIN.RBAC.RBAC_CREATE_SCHEMA() for each database/schema',
            '7. Run ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE() for each domain/team',
            '8. Run ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE() for service accounts',
            '9. Run ADMIN.CLONES.RBAC_SETUP_DEFAULT_CLONE_POLICIES() for clone policies',
            '10. Run ADMIN.SECURITY.RBAC_RUN_SECURITY_SCAN() to establish baseline'
        ),
        'deployment_commands', OBJECT_CONSTRUCT(
            'rbac_schema', 'USE SCHEMA ADMIN.RBAC; -- Deploy: Help, Initial_Config, Identity, Multi_Account, External, Warehouse, Schema, Access_Role, Service_Role, User_Management, Audit, Monitor, Rectify',
            'devops_schema', 'USE SCHEMA ADMIN.DEVOPS; -- Deploy: DevOps, DevOps_Monitoring',
            'clones_schema', 'USE SCHEMA ADMIN.CLONES; -- Deploy: Clone_Management, Clone_Audit, Clone_Monitoring',
            'security_schema', 'USE SCHEMA ADMIN.SECURITY; -- Deploy: Security_Monitoring'
        ),
        'executed_at', CURRENT_TIMESTAMP(),
        'executed_by', CURRENT_USER()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'actions_attempted', v_actions,
            'errors', v_errors
        );
END;
$$;

-- Note: This procedure should be executed by ACCOUNTADMIN
-- GRANT USAGE ON PROCEDURE RBAC_INITIAL_CONFIG(ARRAY, BOOLEAN) TO ROLE ACCOUNTADMIN;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Validate Configuration
 * 
 * Purpose: Standalone validation to check RBAC framework configuration
 *          Can be run at any time to verify framework integrity
 * 
 * Checks performed:
 *   - ADMIN database exists and ownership
 *   - All schemas exist (RBAC, DEVOPS, CLONES, SECURITY)
 *   - System roles exist and hierarchy
 *   - Functional roles exist per environment
 *   - Key grants are in place
 *   - Procedure deployment status
 * 
 * Usage:
 *   CALL RBAC_VALIDATE_CONFIG();
 ******************************************************************************/

CALL RBAC_VALIDATE_CONFIG();

CREATE OR REPLACE SECURE PROCEDURE RBAC_VALIDATE_CONFIG()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_checks ARRAY := ARRAY_CONSTRUCT();
    v_passed INTEGER := 0;
    v_failed INTEGER := 0;
    v_warnings INTEGER := 0;
    v_db_count INTEGER;
    v_owner VARCHAR;
    v_schema_exists INTEGER;
    v_schema_count INTEGER;
    v_role_exists INTEGER;
    v_role_count INTEGER;
    v_func_role_count INTEGER;
    env VARCHAR;
    v_proc_count INTEGER;
    v_public_grant INTEGER;
    v_required_schemas ARRAY;
    schema_idx INTEGER;
    v_schema_name VARCHAR;
    v_system_roles ARRAY;
    role_idx INTEGER;
    v_role_name VARCHAR;
    v_environments ARRAY;
    env_idx INTEGER;
    v_env VARCHAR;
    v_schema_proc_checks ARRAY;
    check_idx INTEGER;
    v_check_obj OBJECT;
    v_min_procs INTEGER;
    v_grant_count INTEGER;
    v_check_schema VARCHAR;
    v_overall_status VARCHAR;
BEGIN
    -- =========================================================================
    -- CHECK 1: ADMIN Database
    -- =========================================================================
    BEGIN
        v_db_count := 0;
        SELECT COUNT(*) INTO v_db_count
        FROM INFORMATION_SCHEMA.DATABASES
        WHERE DATABASE_NAME = 'ADMIN';
        
        IF (v_db_count = 1) THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_DATABASE',
                'status', 'PASS',
                'message', 'ADMIN database exists'
            ));
            v_passed := v_passed + 1;
        ELSE
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_DATABASE',
                'status', 'FAIL',
                'message', 'ADMIN database not found - run RBAC_INITIAL_CONFIG()',
                'remediation', 'CALL RBAC_INITIAL_CONFIG(NULL, FALSE);'
            ));
            v_failed := v_failed + 1;
        END IF;
    EXCEPTION
        WHEN OTHER THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_DATABASE',
                'status', 'ERROR',
                'message', 'Could not check ADMIN database',
                'error', SQLERRM
            ));
            v_failed := v_failed + 1;
    END;
    
    -- =========================================================================
    -- CHECK 2: ADMIN Database Ownership
    -- =========================================================================
    BEGIN
        v_owner := '';
        SELECT DATABASE_OWNER INTO v_owner
        FROM INFORMATION_SCHEMA.DATABASES
        WHERE DATABASE_NAME = 'ADMIN';
        
        IF (v_owner = 'SRS_SYSTEM_ADMIN') THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_OWNERSHIP',
                'status', 'PASS',
                'message', 'ADMIN database owned by SRS_SYSTEM_ADMIN'
            ));
            v_passed := v_passed + 1;
        ELSE
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_OWNERSHIP',
                'status', 'WARNING',
                'message', 'ADMIN database owned by ' || COALESCE(v_owner, 'UNKNOWN') || ' (expected SRS_SYSTEM_ADMIN)',
                'remediation', 'GRANT OWNERSHIP ON DATABASE ADMIN TO ROLE SRS_SYSTEM_ADMIN COPY CURRENT GRANTS;'
            ));
            v_warnings := v_warnings + 1;
        END IF;
    EXCEPTION
        WHEN OTHER THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'ADMIN_OWNERSHIP',
                'status', 'ERROR',
                'message', 'Could not check ADMIN ownership',
                'error', SQLERRM
            ));
            v_failed := v_failed + 1;
    END;
    
    -- =========================================================================
    -- CHECK 3: Required Schemas
    -- =========================================================================
    v_required_schemas := ARRAY_CONSTRUCT('RBAC', 'DEVOPS', 'CLONES', 'SECURITY');
    FOR schema_idx IN 0 TO ARRAY_SIZE(v_required_schemas) - 1 DO
        v_schema_name := v_required_schemas[schema_idx];
        BEGIN
            v_schema_exists := 0;
            SELECT COUNT(*) INTO :v_schema_exists
            FROM ADMIN.INFORMATION_SCHEMA.SCHEMATA
            WHERE SCHEMA_NAME = :v_schema_name;
            
            IF (v_schema_exists = 1) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'SCHEMA_' || v_schema_name,
                    'status', 'PASS',
                    'message', 'ADMIN.' || v_schema_name || ' schema exists'
                ));
                v_passed := v_passed + 1;
            ELSE
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'SCHEMA_' || v_schema_name,
                    'status', 'FAIL',
                    'message', 'ADMIN.' || v_schema_name || ' schema not found',
                    'remediation', 'CREATE SCHEMA IF NOT EXISTS ADMIN.' || v_schema_name || ';'
                ));
                v_failed := v_failed + 1;
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'SCHEMA_' || v_schema_name,
                    'status', 'ERROR',
                    'message', 'Could not check schema ' || v_schema_name,
                    'error', SQLERRM
                ));
                v_failed := v_failed + 1;
        END;
    END FOR;
    
    -- =========================================================================
    -- CHECK 4: System Roles
    -- =========================================================================
    v_system_roles := ARRAY_CONSTRUCT('SRS_ACCOUNT_ADMIN', 'SRS_SECURITY_ADMIN', 'SRS_USER_ADMIN', 'SRS_SYSTEM_ADMIN', 'SRS_DEVOPS');
    FOR role_idx IN 0 TO ARRAY_SIZE(v_system_roles) - 1 DO
        v_role_name := v_system_roles[role_idx];
        BEGIN
            v_role_exists := 0;
            SELECT COUNT(*) INTO :v_role_exists
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
            WHERE DELETED_ON IS NULL AND NAME = :v_role_name;
            
            IF (v_role_exists = 1) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'ROLE_' || v_role_name,
                    'status', 'PASS',
                    'message', 'System role ' || v_role_name || ' exists'
                ));
                v_passed := v_passed + 1;
            ELSE
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'ROLE_' || v_role_name,
                    'status', 'FAIL',
                    'message', 'System role ' || v_role_name || ' not found',
                    'remediation', 'CREATE ROLE IF NOT EXISTS ' || v_role_name || ';'
                ));
                v_failed := v_failed + 1;
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'ROLE_' || v_role_name,
                    'status', 'ERROR',
                    'message', 'Could not check role ' || v_role_name,
                    'error', SQLERRM
                ));
                v_failed := v_failed + 1;
        END;
    END FOR;
    
    -- =========================================================================
    -- CHECK 5: Functional Roles (Sample Check)
    -- =========================================================================
    v_environments := ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PPE', 'PRD');
    FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        v_env := v_environments[env_idx];
        BEGIN
            v_func_role_count := 0;
            SELECT COUNT(*) INTO :v_func_role_count
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
            WHERE DELETED_ON IS NULL AND NAME LIKE ('SRF_' || :v_env || '_%');
            
            IF (v_func_role_count >= 6) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'FUNCTIONAL_ROLES_' || v_env,
                    'status', 'PASS',
                    'message', v_env || ': ' || v_func_role_count::VARCHAR || ' functional roles configured'
                ));
                v_passed := v_passed + 1;
            ELSEIF (v_func_role_count > 0) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'FUNCTIONAL_ROLES_' || v_env,
                    'status', 'WARNING',
                    'message', v_env || ': Only ' || v_func_role_count::VARCHAR || ' functional roles (expected 6)',
                    'remediation', 'Re-run RBAC_INITIAL_CONFIG() to create missing roles'
                ));
                v_warnings := v_warnings + 1;
            ELSE
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'FUNCTIONAL_ROLES_' || v_env,
                    'status', 'FAIL',
                    'message', v_env || ': No functional roles found',
                    'remediation', 'CALL RBAC_INITIAL_CONFIG(ARRAY_CONSTRUCT(''' || v_env || '''), FALSE);'
                ));
                v_failed := v_failed + 1;
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'FUNCTIONAL_ROLES_' || v_env,
                    'status', 'ERROR',
                    'error', SQLERRM
                ));
                v_failed := v_failed + 1;
        END;
    END FOR;
    
    -- =========================================================================
    -- CHECK 6: Procedure Deployment Status
    -- =========================================================================
    v_schema_proc_checks := ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('schema', 'RBAC', 'min_procs', 10),
        OBJECT_CONSTRUCT('schema', 'DEVOPS', 'min_procs', 5),
        OBJECT_CONSTRUCT('schema', 'CLONES', 'min_procs', 5),
        OBJECT_CONSTRUCT('schema', 'SECURITY', 'min_procs', 5)
    );
    
    FOR check_idx IN 0 TO ARRAY_SIZE(v_schema_proc_checks) - 1 DO
        v_check_obj := v_schema_proc_checks[check_idx];
        v_check_schema := v_check_obj:schema::VARCHAR;
        v_min_procs := v_check_obj:min_procs::INTEGER;
        
        BEGIN
            v_proc_count := 0;
            SELECT COUNT(*) INTO :v_proc_count
            FROM ADMIN.INFORMATION_SCHEMA.PROCEDURES
            WHERE PROCEDURE_SCHEMA = :v_check_schema;
            
            IF (v_proc_count >= v_min_procs) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'PROCEDURES_' || v_check_schema,
                    'status', 'PASS',
                    'message', 'ADMIN.' || v_check_schema || ': ' || v_proc_count::VARCHAR || ' procedures deployed'
                ));
                v_passed := v_passed + 1;
            ELSEIF (v_proc_count > 0) THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'PROCEDURES_' || v_check_schema,
                    'status', 'WARNING',
                    'message', 'ADMIN.' || v_check_schema || ': Only ' || v_proc_count::VARCHAR || ' procedures (expected ' || v_min_procs::VARCHAR || '+)',
                    'remediation', 'Deploy remaining procedures to ADMIN.' || v_check_schema
                ));
                v_warnings := v_warnings + 1;
            ELSE
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'PROCEDURES_' || v_check_schema,
                    'status', 'FAIL',
                    'message', 'ADMIN.' || v_check_schema || ': No procedures deployed',
                    'remediation', 'USE SCHEMA ADMIN.' || v_check_schema || '; -- Then run appropriate SQL files'
                ));
                v_failed := v_failed + 1;
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                    'check', 'PROCEDURES_' || v_check_schema,
                    'status', 'ERROR',
                    'message', 'Could not check procedures in ' || v_check_schema,
                    'error', SQLERRM
                ));
                v_failed := v_failed + 1;
        END;
    END FOR;
    
    -- =========================================================================
    -- CHECK 7: Key Grants Verification
    -- =========================================================================
    BEGIN
        v_public_grant := 0;
        SELECT COUNT(*) INTO v_public_grant
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE DELETED_ON IS NULL
          AND GRANTEE_NAME = 'PUBLIC'
          AND NAME = 'ADMIN'
          AND PRIVILEGE = 'USAGE';
        
        IF (v_public_grant > 0) THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'GRANT_PUBLIC_ADMIN',
                'status', 'PASS',
                'message', 'PUBLIC has USAGE on ADMIN database'
            ));
            v_passed := v_passed + 1;
        ELSE
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'GRANT_PUBLIC_ADMIN',
                'status', 'WARNING',
                'message', 'PUBLIC does not have USAGE on ADMIN database',
                'remediation', 'GRANT USAGE ON DATABASE ADMIN TO ROLE PUBLIC;'
            ));
            v_warnings := v_warnings + 1;
        END IF;
    EXCEPTION
        WHEN OTHER THEN
            v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
                'check', 'GRANT_PUBLIC_ADMIN',
                'status', 'ERROR',
                'error', SQLERRM
            ));
            v_failed := v_failed + 1;
    END;
    
    -- =========================================================================
    -- Return Results
    -- =========================================================================
    v_overall_status := 'HEALTHY';
    IF (v_failed > 0) THEN
        v_overall_status := 'CRITICAL';
    ELSEIF (v_warnings > 0) THEN
        v_overall_status := 'WARNING';
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_overall_status,
        'summary', OBJECT_CONSTRUCT(
            'total_checks', ARRAY_SIZE(v_checks),
            'passed', v_passed,
            'failed', v_failed,
            'warnings', v_warnings,
            'health_percentage', ROUND(v_passed * 100.0 / ARRAY_SIZE(v_checks), 1)
        ),
        'checks', v_checks,
        'recommendations', CASE 
            WHEN v_failed > 0 THEN 'Critical issues found. Run remediations or re-run RBAC_INITIAL_CONFIG()'
            WHEN v_warnings > 0 THEN 'Some warnings detected. Review and apply remediations as needed'
            ELSE 'All checks passed. RBAC framework is properly configured'
        END,
        'validated_at', CURRENT_TIMESTAMP(),
        'validated_by', CURRENT_USER()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Validation failed: ' || SQLERRM,
            'sqlcode', SQLCODE
        );
END;
$$;



-- Grant execute on validation procedure
-- GRANT USAGE ON PROCEDURE RBAC_VALIDATE_CONFIG() TO ROLE SRS_SYSTEM_ADMIN;
-- GRANT USAGE ON PROCEDURE RBAC_VALIDATE_CONFIG() TO ROLE SRS_SECURITY_ADMIN;
