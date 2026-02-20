/*******************************************************************************
 * RBAC STORED PROCEDURE: Multi-Account Support
 * 
 * Purpose: Procedures for deploying RBAC framework across multiple Snowflake
 *          accounts within an organization
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     TABLES (3), PROCEDURES (~10)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  ORGADMIN (for org-level operations)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - Organization Admin access required
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SUPPORTED SCENARIOS:
 * 
 *   Scenario 1: ENVIRONMENT-BASED ACCOUNTS
 *   ─────────────────────────────────────────────────────────────────────────
 *   Separate accounts for each environment (DEV, TST, UAT, PPE, PRD)
 *   - Each account contains ALL domains (HR, Sales, Finance)
 *   - Roles: SRF_DEVELOPER, SRA_HR_ACCESS (no env prefix)
 *   - Cross-env promotion via CI/CD deployment
 * 
 *   Scenario 2: DEPARTMENT-BASED ACCOUNTS
 *   ─────────────────────────────────────────────────────────────────────────
 *   Separate accounts for each department/business unit (HR, Sales, Finance)
 *   - Each account contains ALL environments (DEV→PRD)
 *   - Roles: SRF_DEV_DEVELOPER, SRA_DEV_PAYROLL (no domain prefix)
 *   - Cross-dept access via Data Sharing
 * 
 *   Scenario 3: HYBRID (Environment + Department)
 *   ─────────────────────────────────────────────────────────────────────────
 *   Separate accounts for each combination (HR-DEV, HR-PRD, Sales-DEV, etc.)
 *   - Each account is single-purpose
 *   - Roles: SRF_DEVELOPER, SRA_PAYROLL (no prefixes)
 *   - Simplest RBAC per account
 * 
 * ORGANIZATION STRUCTURE:
 *   - ORGADMIN manages account creation and organization settings
 *   - Each account has its own ACCOUNTADMIN
 *   - Data Sharing enables cross-account access
 ******************************************************************************/

-- #############################################################################
-- SECTION 1: MULTI-ACCOUNT INITIAL CONFIGURATION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Initialize Multi-Account RBAC
 * 
 * Purpose: Creates RBAC structure appropriate for the account type
 * 
 * Parameters:
 *   P_ACCOUNT_TYPE    - 'ENVIRONMENT', 'DEPARTMENT', or 'HYBRID'
 *   P_ACCOUNT_PURPOSE - What this account is for:
 *                       ENVIRONMENT: 'DEV', 'TST', 'UAT', 'PPE', 'PRD'
 *                       DEPARTMENT: 'HR', 'SALES', 'FINANCE', etc.
 *                       HYBRID: 'HR_DEV', 'HR_PRD', 'SALES_DEV', etc.
 *   P_ENVIRONMENTS    - For DEPARTMENT type: which environments to create
 *                       Default: all (DEV, TST, UAT, PPE, PRD)
 *   P_SUB_DOMAINS     - Array of sub-domains within this account
 *                       E.g., for HR account: ['PAYROLL', 'BENEFITS', 'RECRUITING']
 *   P_DRY_RUN         - If TRUE, shows what would be created without executing
 * 
 * Execution Role: ACCOUNTADMIN
 ******************************************************************************/


USE DATABASE ADMIN;
USE SCHEMA RBAC;

CREATE OR REPLACE SECURE PROCEDURE RBAC_INITIAL_CONFIG_MULTI_ACCOUNT(
    P_ACCOUNT_TYPE VARCHAR,
    P_ACCOUNT_PURPOSE VARCHAR,
    P_ENVIRONMENTS ARRAY DEFAULT NULL,
    P_SUB_DOMAINS ARRAY DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_environments ARRAY;
    v_sub_domains ARRAY;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_errors ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
    v_role_prefix VARCHAR;
    v_functional_roles ARRAY := ARRAY_CONSTRUCT('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN');
BEGIN
    -- =========================================================================
    -- VALIDATION
    -- =========================================================================
    IF (P_ACCOUNT_TYPE NOT IN ('ENVIRONMENT', 'DEPARTMENT', 'HYBRID')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid account type. Must be: ENVIRONMENT, DEPARTMENT, or HYBRID'
        );
    END IF;
    
    -- Determine environments based on account type
    IF (P_ACCOUNT_TYPE = 'ENVIRONMENT') THEN
        -- Single environment account - no env prefix needed
        v_environments := ARRAY_CONSTRUCT(NULL);
    ELSEIF (P_ACCOUNT_TYPE = 'DEPARTMENT') THEN
        -- Department account has all environments
        v_environments := COALESCE(P_ENVIRONMENTS, ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PPE', 'PRD'));
    ELSE
        -- Hybrid - single purpose, no prefixes
        v_environments := ARRAY_CONSTRUCT(NULL);
    END IF;
    
    -- Default sub-domains if not provided
    v_sub_domains := COALESCE(P_SUB_DOMAINS, ARRAY_CONSTRUCT('DEFAULT'));

    -- =========================================================================
    -- SECTION 1: ACCOUNT SETTINGS
    -- =========================================================================
    v_sql := 'ALTER ACCOUNT SET DEFAULT_SECONDARY_ROLES = (''ALL'')';
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'ACCOUNT_SETTINGS', 'sql', v_sql));
    IF (NOT P_DRY_RUN) THEN
        BEGIN
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION WHEN OTHER THEN
            v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
        END;
    END IF;

    -- =========================================================================
    -- SECTION 2: SYSTEM ROLES (SRS) - Same for all account types
    -- =========================================================================
    LET v_system_roles ARRAY := ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('name', 'SRS_ACCOUNT_ADMIN', 'comment', 'Account-level administration'),
        OBJECT_CONSTRUCT('name', 'SRS_SECURITY_ADMIN', 'comment', 'Security and access management'),
        OBJECT_CONSTRUCT('name', 'SRS_USER_ADMIN', 'comment', 'User management'),
        OBJECT_CONSTRUCT('name', 'SRS_SYSTEM_ADMIN', 'comment', 'System administration'),
        OBJECT_CONSTRUCT('name', 'SRS_DATA_SHARING_ADMIN', 'comment', 'Cross-account data sharing management')
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_roles) - 1 DO
        LET v_role_obj OBJECT := v_system_roles[i];
        v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_obj:name::VARCHAR || 
                 ' COMMENT = ''' || v_role_obj:comment::VARCHAR || ' [' || P_ACCOUNT_PURPOSE || ']''';
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'SYSTEM_ROLES', 'sql', v_sql));
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- System role hierarchy
    LET v_system_grants ARRAY := ARRAY_CONSTRUCT(
        'GRANT ROLE SRS_ACCOUNT_ADMIN TO ROLE ACCOUNTADMIN',
        'GRANT ROLE SRS_SECURITY_ADMIN TO ROLE SECURITYADMIN',
        'GRANT ROLE SRS_USER_ADMIN TO ROLE USERADMIN',
        'GRANT ROLE SRS_SYSTEM_ADMIN TO ROLE SYSADMIN',
        'GRANT ROLE SRS_SECURITY_ADMIN TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT ROLE SRS_USER_ADMIN TO ROLE SRS_SECURITY_ADMIN',
        'GRANT ROLE SRS_SYSTEM_ADMIN TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT ROLE SRS_DATA_SHARING_ADMIN TO ROLE SRS_ACCOUNT_ADMIN'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_grants) - 1 DO
        v_sql := v_system_grants[i];
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'SYSTEM_HIERARCHY', 'sql', v_sql));
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- System role privileges
    LET v_system_privs ARRAY := ARRAY_CONSTRUCT(
        'GRANT CREATE ROLE ON ACCOUNT TO ROLE SRS_SECURITY_ADMIN',
        'GRANT MANAGE GRANTS ON ACCOUNT TO ROLE SRS_SECURITY_ADMIN',
        'GRANT CREATE USER ON ACCOUNT TO ROLE SRS_USER_ADMIN',
        'GRANT MONITOR USAGE ON ACCOUNT TO ROLE SRS_ACCOUNT_ADMIN',
        'GRANT CREATE SHARE ON ACCOUNT TO ROLE SRS_DATA_SHARING_ADMIN',
        'GRANT IMPORT SHARE ON ACCOUNT TO ROLE SRS_DATA_SHARING_ADMIN'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_system_privs) - 1 DO
        v_sql := v_system_privs[i];
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'SYSTEM_PRIVILEGES', 'sql', v_sql));
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION WHEN OTHER THEN
                v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
            END;
        END IF;
    END FOR;

    -- =========================================================================
    -- SECTION 3: FUNCTIONAL ROLES (SRF)
    -- =========================================================================
    FOR env_idx IN 0 TO ARRAY_SIZE(v_environments) - 1 DO
        LET v_env VARCHAR := v_environments[env_idx]::VARCHAR;
        
        FOR role_idx IN 0 TO ARRAY_SIZE(v_functional_roles) - 1 DO
            LET v_role_level VARCHAR := v_functional_roles[role_idx];
            LET v_role_name VARCHAR;
            
            -- Build role name based on account type
            IF (v_env IS NULL) THEN
                v_role_name := 'SRF_' || v_role_level;  -- No prefix
            ELSE
                v_role_name := 'SRF_' || v_env || '_' || v_role_level;  -- With env prefix
            END IF;
            
            v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_name || 
                     ' COMMENT = ''Functional: ' || v_role_level || ' [' || P_ACCOUNT_PURPOSE || ']''';
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'section', 'FUNCTIONAL_ROLES', 
                'role', v_role_name,
                'sql', v_sql
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
        
        -- Create hierarchy for this environment's functional roles
        LET v_env_prefix VARCHAR := IFF(v_env IS NULL, '', v_env || '_');
        LET v_hierarchy ARRAY := ARRAY_CONSTRUCT(
            'GRANT ROLE SRF_' || v_env_prefix || 'END_USER TO ROLE SRF_' || v_env_prefix || 'ANALYST',
            'GRANT ROLE SRF_' || v_env_prefix || 'ANALYST TO ROLE SRF_' || v_env_prefix || 'DEVELOPER',
            'GRANT ROLE SRF_' || v_env_prefix || 'DEVELOPER TO ROLE SRF_' || v_env_prefix || 'TEAM_LEADER',
            'GRANT ROLE SRF_' || v_env_prefix || 'TEAM_LEADER TO ROLE SRF_' || v_env_prefix || 'DATA_SCIENTIST',
            'GRANT ROLE SRF_' || v_env_prefix || 'DATA_SCIENTIST TO ROLE SRF_' || v_env_prefix || 'DBADMIN',
            'GRANT ROLE SRF_' || v_env_prefix || 'DBADMIN TO ROLE SRS_SYSTEM_ADMIN'
        );
        
        FOR h_idx IN 0 TO ARRAY_SIZE(v_hierarchy) - 1 DO
            v_sql := v_hierarchy[h_idx];
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'FUNCTIONAL_HIERARCHY', 'sql', v_sql));
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
        
        -- DBADMIN privileges
        LET v_dbadmin_role VARCHAR := 'SRF_' || v_env_prefix || 'DBADMIN';
        LET v_dbadmin_privs ARRAY := ARRAY_CONSTRUCT(
            'GRANT CREATE DATABASE ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT CREATE WAREHOUSE ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT APPLY ROW ACCESS POLICY ON ACCOUNT TO ROLE ' || v_dbadmin_role,
            'GRANT APPLY TAG ON ACCOUNT TO ROLE ' || v_dbadmin_role
        );
        
        FOR p_idx IN 0 TO ARRAY_SIZE(v_dbadmin_privs) - 1 DO
            v_sql := v_dbadmin_privs[p_idx];
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('section', 'DBADMIN_PRIVILEGES', 'sql', v_sql));
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT('sql', v_sql, 'error', SQLERRM));
                END;
            END IF;
        END FOR;
    END FOR;

    -- =========================================================================
    -- RETURN RESULTS
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', IFF(ARRAY_SIZE(v_errors) = 0, 'SUCCESS', 'PARTIAL_SUCCESS'),
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'account_type', P_ACCOUNT_TYPE,
        'account_purpose', P_ACCOUNT_PURPOSE,
        'environments_created', v_environments,
        'role_naming', CASE P_ACCOUNT_TYPE
            WHEN 'ENVIRONMENT' THEN 'SRF_<LEVEL>, SRA_<DOMAIN>_ACCESS (no env prefix)'
            WHEN 'DEPARTMENT' THEN 'SRF_<ENV>_<LEVEL>, SRA_<ENV>_<SUBDOMAIN>_ACCESS (no dept prefix)'
            WHEN 'HYBRID' THEN 'SRF_<LEVEL>, SRA_<SUBDOMAIN>_ACCESS (no prefixes)'
        END,
        'actions_count', ARRAY_SIZE(v_actions),
        'errors_count', ARRAY_SIZE(v_errors),
        'actions', v_actions,
        'errors', v_errors,
        'next_steps', ARRAY_CONSTRUCT(
            '1. Create warehouses: CALL RBAC_CREATE_WAREHOUSE_MULTI_ACCOUNT(...)',
            '2. Create schemas: CALL RBAC_CREATE_SCHEMA_MULTI_ACCOUNT(...)',
            '3. Create access roles for sub-domains',
            '4. Setup data sharing if cross-account access needed',
            '5. Configure SSO/SCIM for this account'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Access Role (Multi-Account)
 * 
 * Purpose: Creates access roles with naming appropriate for account type
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE_MULTI_ACCOUNT(
    P_ACCOUNT_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,        -- NULL for ENVIRONMENT/HYBRID types
    P_SUB_DOMAIN VARCHAR,         -- Sub-domain within account (e.g., PAYROLL, ORDERS)
    P_COMMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_role_name VARCHAR;
    v_sql VARCHAR;
BEGIN
    -- Build role name based on account type
    IF (P_ACCOUNT_TYPE = 'ENVIRONMENT') THEN
        -- Environment account: SRA_<SUBDOMAIN>_ACCESS
        v_role_name := 'SRA_' || UPPER(P_SUB_DOMAIN) || '_ACCESS';
    ELSEIF (P_ACCOUNT_TYPE = 'DEPARTMENT') THEN
        -- Department account: SRA_<ENV>_<SUBDOMAIN>_ACCESS
        v_role_name := 'SRA_' || UPPER(P_ENVIRONMENT) || '_' || UPPER(P_SUB_DOMAIN) || '_ACCESS';
    ELSE
        -- Hybrid: SRA_<SUBDOMAIN>_ACCESS (no prefixes)
        v_role_name := 'SRA_' || UPPER(P_SUB_DOMAIN) || '_ACCESS';
    END IF;
    
    -- Create the access role
    v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_name || 
             ' COMMENT = ''' || COALESCE(P_COMMENT, 'Access role for ' || P_SUB_DOMAIN) || '''';
    EXECUTE IMMEDIATE v_sql;
    
    -- Grant to security admin
    v_sql := 'GRANT ROLE ' || v_role_name || ' TO ROLE SRS_SECURITY_ADMIN';
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'role_name', v_role_name,
        'account_type', P_ACCOUNT_TYPE,
        'environment', P_ENVIRONMENT,
        'sub_domain', P_SUB_DOMAIN
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 2: DATA SHARING PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Outbound Share
 * 
 * Purpose: Creates a share for providing data to other accounts
 * 
 * Parameters:
 *   P_SHARE_NAME        - Name of the share
 *   P_DATABASE          - Database to share from
 *   P_SCHEMAS           - Array of schema names to include
 *   P_CONSUMER_ACCOUNTS - Array of account identifiers to share with
 *   P_COMMENT           - Description of the share
 * 
 * Execution Role: SRS_DATA_SHARING_ADMIN or ACCOUNTADMIN
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_CREATE_OUTBOUND_SHARE(
    P_SHARE_NAME VARCHAR,
    P_DATABASE VARCHAR,
    P_SCHEMAS ARRAY,
    P_CONSUMER_ACCOUNTS ARRAY,
    P_COMMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Create the share
    v_sql := 'CREATE SHARE IF NOT EXISTS ' || P_SHARE_NAME || 
             ' COMMENT = ''' || COALESCE(P_COMMENT, 'Outbound data share') || '''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_SHARE', 'sql', v_sql));
    
    -- Grant usage on database
    v_sql := 'GRANT USAGE ON DATABASE ' || P_DATABASE || ' TO SHARE ' || P_SHARE_NAME;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_DATABASE', 'sql', v_sql));
    
    -- Grant usage on each schema and select on tables
    FOR i IN 0 TO ARRAY_SIZE(P_SCHEMAS) - 1 DO
        LET v_schema VARCHAR := P_SCHEMAS[i]::VARCHAR;
        
        v_sql := 'GRANT USAGE ON SCHEMA ' || P_DATABASE || '.' || v_schema || ' TO SHARE ' || P_SHARE_NAME;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_SCHEMA', 'schema', v_schema));
        
        v_sql := 'GRANT SELECT ON ALL TABLES IN SCHEMA ' || P_DATABASE || '.' || v_schema || ' TO SHARE ' || P_SHARE_NAME;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_TABLES', 'schema', v_schema));
        
        v_sql := 'GRANT SELECT ON ALL VIEWS IN SCHEMA ' || P_DATABASE || '.' || v_schema || ' TO SHARE ' || P_SHARE_NAME;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_VIEWS', 'schema', v_schema));
    END FOR;
    
    -- Add consumer accounts
    FOR i IN 0 TO ARRAY_SIZE(P_CONSUMER_ACCOUNTS) - 1 DO
        LET v_account VARCHAR := P_CONSUMER_ACCOUNTS[i]::VARCHAR;
        v_sql := 'ALTER SHARE ' || P_SHARE_NAME || ' ADD ACCOUNTS = ' || v_account;
        BEGIN
            EXECUTE IMMEDIATE v_sql;
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'ADD_CONSUMER', 'account', v_account));
        EXCEPTION
            WHEN OTHER THEN
                v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'ADD_CONSUMER_FAILED', 'account', v_account, 'error', SQLERRM));
        END;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'share_name', P_SHARE_NAME,
        'source_database', P_DATABASE,
        'schemas_shared', P_SCHEMAS,
        'consumer_accounts', P_CONSUMER_ACCOUNTS,
        'actions', v_actions,
        'consumer_instructions', ARRAY_CONSTRUCT(
            'In each consumer account, run:',
            'CREATE DATABASE <local_name> FROM SHARE ' || CURRENT_ACCOUNT() || '.' || P_SHARE_NAME || ';',
            'GRANT IMPORTED PRIVILEGES ON DATABASE <local_name> TO ROLE <access_role>;'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Mount Inbound Share
 * 
 * Purpose: Mounts a share from another account and grants access via RBAC
 * 
 * Parameters:
 *   P_SHARE_IDENTIFIER  - Full share identifier (org.account.share_name)
 *   P_LOCAL_DB_NAME     - Local database name to create
 *   P_ACCESS_ROLE       - RBAC access role to grant read access
 *   P_COMMENT           - Description
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_MOUNT_INBOUND_SHARE(
    P_SHARE_IDENTIFIER VARCHAR,
    P_LOCAL_DB_NAME VARCHAR,
    P_ACCESS_ROLE VARCHAR,
    P_COMMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    -- Create database from share
    v_sql := 'CREATE OR REPLACE DATABASE ' || P_LOCAL_DB_NAME || 
             ' FROM SHARE ' || P_SHARE_IDENTIFIER ||
             ' COMMENT = ''' || COALESCE(P_COMMENT, 'Mounted from ' || P_SHARE_IDENTIFIER) || '''';
    EXECUTE IMMEDIATE v_sql;
    
    -- Grant imported privileges to the access role
    v_sql := 'GRANT IMPORTED PRIVILEGES ON DATABASE ' || P_LOCAL_DB_NAME || ' TO ROLE ' || P_ACCESS_ROLE;
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'share_identifier', P_SHARE_IDENTIFIER,
        'local_database', P_LOCAL_DB_NAME,
        'access_role', P_ACCESS_ROLE,
        'access_granted', 'Users with ' || P_ACCESS_ROLE || ' can now query ' || P_LOCAL_DB_NAME
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Cross-Account Access Role
 * 
 * Purpose: Creates an access role specifically for shared data from another account
 * 
 * Parameters:
 *   P_SOURCE_ACCOUNT    - Source account name (for naming)
 *   P_SOURCE_DOMAIN     - Source domain/department
 *   P_ENVIRONMENT       - Environment (NULL if not applicable)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SHARED_DATA_ACCESS_ROLE(
    P_SOURCE_ACCOUNT VARCHAR,
    P_SOURCE_DOMAIN VARCHAR,
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_COMMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_role_name VARCHAR;
    v_sql VARCHAR;
BEGIN
    -- Build role name
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_role_name := 'SRA_' || P_ENVIRONMENT || '_SHARED_' || UPPER(P_SOURCE_DOMAIN) || '_ACCESS';
    ELSE
        v_role_name := 'SRA_SHARED_' || UPPER(P_SOURCE_DOMAIN) || '_ACCESS';
    END IF;
    
    -- Create the role
    v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_role_name || 
             ' COMMENT = ''' || COALESCE(P_COMMENT, 'Access to shared data from ' || P_SOURCE_ACCOUNT || ' ' || P_SOURCE_DOMAIN) || '''';
    EXECUTE IMMEDIATE v_sql;
    
    -- Grant to security admin
    v_sql := 'GRANT ROLE ' || v_role_name || ' TO ROLE SRS_SECURITY_ADMIN';
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'role_name', v_role_name,
        'purpose', 'Grant this role to users who need access to ' || P_SOURCE_DOMAIN || ' data from ' || P_SOURCE_ACCOUNT,
        'next_step', 'Mount the share and grant to this role: CALL RBAC_MOUNT_INBOUND_SHARE(..., ''' || v_role_name || ''', ...)'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Account Shares
 * 
 * Purpose: Lists all inbound and outbound shares for this account
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_LIST_ACCOUNT_SHARES()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_outbound_shares ARRAY;
    v_inbound_shares ARRAY;
BEGIN
    -- Get outbound shares (this account is provider)
    v_outbound_shares := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'share_name', "name",
            'database', "database_name",
            'kind', "kind",
            'created_on', "created_on"
        ))
        FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
    );
    
    SHOW SHARES;
    
    -- Note: Inbound shares require SHOW SHARES and filtering
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'account', CURRENT_ACCOUNT(),
        'note', 'Run SHOW SHARES to see full share details',
        'outbound_shares_query', 'SHOW SHARES LIKE ''%'' STARTS WITH ''' || CURRENT_ACCOUNT() || '''',
        'inbound_shares_query', 'SHOW SHARES;  -- Filter for kind = INBOUND'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: CROSS-ACCOUNT USER MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Multi-Account SCIM
 * 
 * Purpose: Guidance for setting up SCIM across multiple accounts
 * 
 * Note: Each account needs its own SCIM integration. The IdP can provision
 *       users to multiple accounts based on group membership.
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_MULTI_ACCOUNT_SCIM_GUIDE(
    P_ACCOUNT_TYPE VARCHAR,
    P_IDP_TYPE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'account', CURRENT_ACCOUNT(),
        'account_type', P_ACCOUNT_TYPE,
        'idp_type', P_IDP_TYPE,
        'scim_configuration', OBJECT_CONSTRUCT(
            'integration_per_account', TRUE,
            'recommendation', 'Create separate SCIM integration in each Snowflake account',
            'idp_setup', CASE P_IDP_TYPE
                WHEN 'OKTA' THEN 'Create separate Okta app per Snowflake account, or use single app with account-specific groups'
                WHEN 'AZURE_AD' THEN 'Create separate Enterprise Application per Snowflake account'
            END
        ),
        'ad_group_strategy', CASE P_ACCOUNT_TYPE
            WHEN 'ENVIRONMENT' THEN OBJECT_CONSTRUCT(
                'pattern', 'SF_<ACCOUNT>_<ROLE>',
                'examples', ARRAY_CONSTRUCT(
                    'SF_DEV_DEVELOPER → provisions to DEV account, gets SRF_DEVELOPER',
                    'SF_PRD_ANALYST → provisions to PRD account, gets SRF_ANALYST',
                    'SF_DEV_HR_ACCESS → provisions to DEV account, gets SRA_HR_ACCESS'
                )
            )
            WHEN 'DEPARTMENT' THEN OBJECT_CONSTRUCT(
                'pattern', 'SF_<ACCOUNT>_<ENV>_<ROLE>',
                'examples', ARRAY_CONSTRUCT(
                    'SF_HR_DEV_DEVELOPER → provisions to HR account, gets SRF_DEV_DEVELOPER',
                    'SF_SALES_PRD_ANALYST → provisions to SALES account, gets SRF_PRD_ANALYST'
                )
            )
            WHEN 'HYBRID' THEN OBJECT_CONSTRUCT(
                'pattern', 'SF_<ACCOUNT>_<ROLE>',
                'examples', ARRAY_CONSTRUCT(
                    'SF_HR_DEV_DEVELOPER → provisions to HR-DEV account, gets SRF_DEVELOPER',
                    'SF_HR_PRD_ANALYST → provisions to HR-PRD account, gets SRF_ANALYST'
                )
            )
        END,
        'setup_steps', ARRAY_CONSTRUCT(
            '1. In this account, run: CALL RBAC_SETUP_MODEL_A_BASIC_SCIM or RBAC_SETUP_MODEL_B_FULL_SCIM',
            '2. Generate SCIM token for this account',
            '3. In IdP, create app/integration for this account',
            '4. Configure SCIM endpoint with this account''s URL and token',
            '5. Assign users to account-specific groups in IdP',
            '6. Repeat for each Snowflake account in organization'
        )
    );
END;
$$;

-- #############################################################################
-- SECTION 4: ORGANIZATION MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Organization Account Inventory
 * 
 * Purpose: Lists recommended RBAC configuration for each account in org
 * 
 * Note: Must be run by ORGADMIN
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_ORG_ACCOUNT_INVENTORY()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'note', 'Run as ORGADMIN to see all accounts',
        'query', 'SHOW ORGANIZATION ACCOUNTS;',
        'recommended_setup_per_account', ARRAY_CONSTRUCT(
            '1. Determine account type: ENVIRONMENT, DEPARTMENT, or HYBRID',
            '2. Run RBAC_INITIAL_CONFIG_MULTI_ACCOUNT with appropriate parameters',
            '3. Setup SCIM integration for the account',
            '4. Configure data sharing for cross-account access',
            '5. Document account purpose and RBAC configuration'
        ),
        'account_types', OBJECT_CONSTRUCT(
            'ENVIRONMENT', 'Accounts named: DEV, TST, UAT, PPE, PRD',
            'DEPARTMENT', 'Accounts named: HR, SALES, FINANCE, etc.',
            'HYBRID', 'Accounts named: HR_DEV, HR_PRD, SALES_DEV, etc.'
        )
    );
END;
$$;

-- #############################################################################
-- GRANT EXECUTE PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE RBAC_INITIAL_CONFIG_MULTI_ACCOUNT(VARCHAR, VARCHAR, ARRAY, ARRAY, BOOLEAN) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_CREATE_ACCESS_ROLE_MULTI_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- NOTE: Uncomment these after creating SRS_DATA_SHARING_ADMIN role
-- CREATE ROLE IF NOT EXISTS SRS_DATA_SHARING_ADMIN;
-- GRANT ROLE SRS_DATA_SHARING_ADMIN TO ROLE ACCOUNTADMIN;
-- GRANT USAGE ON PROCEDURE RBAC_CREATE_OUTBOUND_SHARE(VARCHAR, VARCHAR, ARRAY, ARRAY, VARCHAR) TO ROLE SRS_DATA_SHARING_ADMIN;
-- GRANT USAGE ON PROCEDURE RBAC_MOUNT_INBOUND_SHARE(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_DATA_SHARING_ADMIN;

--GRANT USAGE ON PROCEDURE RBAC_CREATE_SHARED_DATA_ACCESS_ROLE(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
--GRANT USAGE ON PROCEDURE RBAC_LIST_ACCOUNT_SHARES() TO ROLE SRS_DATA_SHARING_ADMIN;
--RANT USAGE ON PROCEDURE RBAC_MULTI_ACCOUNT_SCIM_GUIDE(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_ORG_ACCOUNT_INVENTORY() TO ROLE ORGADMIN;
