/*******************************************************************************
 * RBAC STORED PROCEDURE: User Management
 * 
 * Purpose: Procedures for managing user accounts and role assignments
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURES (4)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedures)
 *   Execution Role:  SRS_USER_ADMIN, SRS_SECURITY_ADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - SRS_USER_ADMIN, SRS_SECURITY_ADMIN roles must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ACCOUNT TYPES:
 *   - PERSON: Human users (created via SCIM, configured here)
 *   - SERVICE: Service accounts (created and configured here)
 *   - LEGACY_SERVICE: Legacy service accounts
 * 
 * Procedures:
 *   - RBAC_CREATE_SERVICE_ACCOUNT: Creates service account with key pair auth
 *   - RBAC_CONFIGURE_USER: Configures existing SCIM-provisioned user
 *   - RBAC_DISABLE_USER: Disables a user account
 *   - RBAC_LIST_USER_ACCESS: Lists all access for a user
 ******************************************************************************/

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Service Account
 * 
 * Purpose: Creates a service account with TYPE='SERVICE' and RSA key pair
 *          authentication. Service accounts do NOT use passwords.
 * 
 * Parameters:
 *   P_ACCOUNT_NAME      - Service account name (recommended: SVC_<APP>_<PURPOSE>)
 *   P_RSA_PUBLIC_KEY    - RSA public key for authentication (required)
 *   P_ENVIRONMENT       - Environment: DEV, TST, UAT, PPE, PRD
 *   P_DOMAIN            - Domain for access role (e.g., HR, SALES)
 *   P_CAPABILITY_LEVEL  - Capability level: END_USER, ANALYST, etc.
 *   P_DEFAULT_WAREHOUSE - Default warehouse for the account
 *   P_COMMENT           - Description of the service account
 *   P_RSA_PUBLIC_KEY_2  - Optional second RSA key for key rotation
 * 
 * Execution Role: SRS_USER_ADMIN or SRS_SECURITY_ADMIN
 * 
 * Usage Example:
 *   CALL RBAC_CREATE_SERVICE_ACCOUNT(
 *       'SVC_POWERBI_HR',
 *       'MIIBIjANBgkqh...public_key_here...',
 *       'PRD',
 *       'HR',
 *       'ANALYST',
 *       'PRD_WH',
 *       'Power BI service account for HR reporting',
 *       NULL
 *   );
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT(
    P_ACCOUNT_NAME VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_DEFAULT_WAREHOUSE VARCHAR,
    P_COMMENT VARCHAR DEFAULT 'Service account',
    P_RSA_PUBLIC_KEY_2 VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_account_exists BOOLEAN;
    v_role_exists BOOLEAN;
BEGIN
    -- =========================================================================
    -- VALIDATION
    -- =========================================================================
    
    -- Validate account name format (recommended: SVC_*)
    IF P_ACCOUNT_NAME IS NULL OR LENGTH(P_ACCOUNT_NAME) < 3 THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid account name. Must be at least 3 characters.',
            'recommendation', 'Use naming convention: SVC_<APPLICATION>_<PURPOSE>'
        );
    END IF;
    
    -- Validate RSA public key is provided
    IF P_RSA_PUBLIC_KEY IS NULL OR LENGTH(P_RSA_PUBLIC_KEY) < 100 THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'RSA public key is required for service accounts.',
            'hint', 'Generate key pair using: openssl genrsa -out rsa_key.p8 2048'
        );
    END IF;
    
    -- Validate environment
    IF P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate capability level
    IF P_CAPABILITY_LEVEL NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid capability level. Must be one of: END_USER, ANALYST, DEVELOPER, TEAM_LEADER, DATA_SCIENTIST, DBADMIN'
        );
    END IF;
    
    -- Check if account already exists
    SELECT COUNT(*) > 0 INTO :v_account_exists
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = UPPER(:P_ACCOUNT_NAME)
      AND DELETED_ON IS NULL;
    
    IF v_account_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Account already exists',
            'account_name', P_ACCOUNT_NAME,
            'hint', 'Use RBAC_GRANT_SERVICE_ACCOUNT to assign roles to existing accounts'
        );
    END IF;
    
    -- Derive service role name
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN) || '_' || P_CAPABILITY_LEVEL;
    
    -- Check if service role exists
    SELECT COUNT(*) > 0 INTO :v_role_exists
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
    WHERE NAME = :v_service_role
      AND DELETED_ON IS NULL;
    
    IF NOT v_role_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Service wrapper role does not exist. Create it first.',
            'required_role', v_service_role,
            'hint', 'Run RBAC_CREATE_SERVICE_ROLE(''' || P_ENVIRONMENT || ''', ''' || P_DOMAIN || ''', ''' || P_CAPABILITY_LEVEL || ''', ''description'')'
        );
    END IF;

    -- =========================================================================
    -- CREATE SERVICE ACCOUNT
    -- =========================================================================
    
    -- Build CREATE USER statement
    IF P_RSA_PUBLIC_KEY_2 IS NOT NULL THEN
        v_sql := 'CREATE USER ' || P_ACCOUNT_NAME ||
                 ' TYPE = SERVICE' ||
                 ' RSA_PUBLIC_KEY = ''' || P_RSA_PUBLIC_KEY || '''' ||
                 ' RSA_PUBLIC_KEY_2 = ''' || P_RSA_PUBLIC_KEY_2 || '''' ||
                 ' DEFAULT_ROLE = ''' || v_service_role || '''' ||
                 ' DEFAULT_WAREHOUSE = ''' || P_DEFAULT_WAREHOUSE || '''' ||
                 ' COMMENT = ''' || P_COMMENT || '''';
    ELSE
        v_sql := 'CREATE USER ' || P_ACCOUNT_NAME ||
                 ' TYPE = SERVICE' ||
                 ' RSA_PUBLIC_KEY = ''' || P_RSA_PUBLIC_KEY || '''' ||
                 ' DEFAULT_ROLE = ''' || v_service_role || '''' ||
                 ' DEFAULT_WAREHOUSE = ''' || P_DEFAULT_WAREHOUSE || '''' ||
                 ' COMMENT = ''' || P_COMMENT || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'CREATE_SERVICE_ACCOUNT',
        'account', P_ACCOUNT_NAME,
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- GRANT SERVICE ROLE
    -- =========================================================================
    v_sql := 'GRANT ROLE ' || v_service_role || ' TO USER ' || P_ACCOUNT_NAME;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_SERVICE_ROLE',
        'role', v_service_role,
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- GRANT WAREHOUSE USAGE
    -- =========================================================================
    v_sql := 'GRANT USAGE ON WAREHOUSE ' || P_DEFAULT_WAREHOUSE || ' TO ROLE ' || v_service_role;
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_WAREHOUSE_USAGE',
            'warehouse', P_DEFAULT_WAREHOUSE,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'GRANT_WAREHOUSE_USAGE',
                'warehouse', P_DEFAULT_WAREHOUSE,
                'status', 'ALREADY_GRANTED_OR_ERROR',
                'note', SQLERRM
            ));
    END;

    -- =========================================================================
    -- Return Success
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'account_name', P_ACCOUNT_NAME,
        'account_type', 'SERVICE',
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN,
        'capability_level', P_CAPABILITY_LEVEL,
        'service_role', v_service_role,
        'default_warehouse', P_DEFAULT_WAREHOUSE,
        'authentication', 'RSA_KEY_PAIR',
        'has_backup_key', (P_RSA_PUBLIC_KEY_2 IS NOT NULL),
        'actions', v_actions,
        'connection_info', OBJECT_CONSTRUCT(
            'authenticator', 'SNOWFLAKE_JWT',
            'account', CURRENT_ACCOUNT(),
            'user', P_ACCOUNT_NAME,
            'role', v_service_role,
            'warehouse', P_DEFAULT_WAREHOUSE
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'account_name', P_ACCOUNT_NAME,
            'actions_attempted', v_actions
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Configure User (SCIM-provisioned)
 * 
 * Purpose: Configures role assignments for an existing user that was
 *          provisioned via SCIM (Identity Provider)
 * 
 * NOTE: This procedure does NOT create users. Users must already exist
 *       (typically created via SCIM from Okta, Azure AD, etc.)
 * 
 * Parameters:
 *   P_USER_NAME         - Username (must already exist)
 *   P_ENVIRONMENT       - Environment: DEV, TST, UAT, PPE, PRD
 *   P_DOMAIN            - Primary domain for access (e.g., HR, SALES)
 *   P_CAPABILITY_LEVEL  - Capability level: END_USER, ANALYST, DEVELOPER, etc.
 *   P_DEFAULT_WAREHOUSE - Default warehouse to set
 *   P_ADDITIONAL_DOMAINS- Optional: Array of additional domains for access
 * 
 * Execution Role: SRS_SECURITY_ADMIN
 * 
 * Usage Examples:
 *   -- Configure user with single domain access
 *   CALL RBAC_CONFIGURE_USER('john.doe@company.com', 'DEV', 'HR', 'DEVELOPER', 'DEV_WH', NULL);
 *   
 *   -- Configure user with multiple domain access
 *   CALL RBAC_CONFIGURE_USER('jane.doe@company.com', 'PRD', 'SALES', 'ANALYST', 'PRD_WH', 
 *        ARRAY_CONSTRUCT('HR', 'FINANCE'));
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CONFIGURE_USER(
    P_USER_NAME VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_DEFAULT_WAREHOUSE VARCHAR,
    P_ADDITIONAL_DOMAINS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_functional_role VARCHAR;
    v_access_role VARCHAR;
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_user_type VARCHAR;
    v_access_role_exists BOOLEAN;
    i INTEGER;
    v_add_domain VARCHAR;
    v_add_access_role VARCHAR;
BEGIN
    -- =========================================================================
    -- VALIDATION
    -- =========================================================================
    
    -- Check if user exists
    SELECT COALESCE(TYPE, 'PERSON') INTO :v_user_type
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = UPPER(:P_USER_NAME)
      AND DELETED_ON IS NULL;
    
    IF v_user_type IS NULL THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User does not exist. Users must be provisioned via SCIM before configuration.',
            'user_name', P_USER_NAME,
            'hint', 'Ensure user is provisioned from your Identity Provider (Okta, Azure AD, etc.)'
        );
    END IF;
    
    -- Check if user is a service account (should use different procedure)
    IF v_user_type IN ('SERVICE', 'LEGACY_SERVICE') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User is a service account. Use RBAC_GRANT_SERVICE_ACCOUNT instead.',
            'user_name', P_USER_NAME,
            'user_type', v_user_type
        );
    END IF;
    
    -- Validate environment
    IF P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate capability level
    IF P_CAPABILITY_LEVEL NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid capability level. Must be one of: END_USER, ANALYST, DEVELOPER, TEAM_LEADER, DATA_SCIENTIST, DBADMIN'
        );
    END IF;
    
    -- Derive role names
    v_functional_role := 'SRF_' || P_ENVIRONMENT || '_' || P_CAPABILITY_LEVEL;
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN) || '_ACCESS';
    
    -- Check if access role exists
    SELECT COUNT(*) > 0 INTO :v_access_role_exists
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
    WHERE NAME = :v_access_role
      AND DELETED_ON IS NULL;
    
    IF NOT v_access_role_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Access role does not exist. Create it first.',
            'required_role', v_access_role,
            'hint', 'Run RBAC_CREATE_ACCESS_ROLE(''' || P_ENVIRONMENT || ''', ''' || P_DOMAIN || ''', ''description'')'
        );
    END IF;

    -- =========================================================================
    -- GRANT FUNCTIONAL ROLE
    -- =========================================================================
    v_sql := 'GRANT ROLE ' || v_functional_role || ' TO USER ' || P_USER_NAME;
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_FUNCTIONAL_ROLE',
            'role', v_functional_role,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'GRANT_FUNCTIONAL_ROLE',
                'role', v_functional_role,
                'status', 'ALREADY_GRANTED_OR_ERROR',
                'note', SQLERRM
            ));
    END;

    -- =========================================================================
    -- GRANT PRIMARY ACCESS ROLE
    -- =========================================================================
    v_sql := 'GRANT ROLE ' || v_access_role || ' TO USER ' || P_USER_NAME;
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_ACCESS_ROLE',
            'role', v_access_role,
            'domain', P_DOMAIN,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'GRANT_ACCESS_ROLE',
                'role', v_access_role,
                'domain', P_DOMAIN,
                'status', 'ALREADY_GRANTED_OR_ERROR',
                'note', SQLERRM
            ));
    END;

    -- =========================================================================
    -- GRANT ADDITIONAL ACCESS ROLES
    -- =========================================================================
    IF P_ADDITIONAL_DOMAINS IS NOT NULL AND ARRAY_SIZE(P_ADDITIONAL_DOMAINS) > 0 THEN
        FOR i IN 0 TO ARRAY_SIZE(P_ADDITIONAL_DOMAINS) - 1 DO
            v_add_domain := P_ADDITIONAL_DOMAINS[i]::VARCHAR;
            v_add_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(v_add_domain) || '_ACCESS';
            
            v_sql := 'GRANT ROLE ' || v_add_access_role || ' TO USER ' || P_USER_NAME;
            BEGIN
                EXECUTE IMMEDIATE v_sql;
                v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                    'action', 'GRANT_ADDITIONAL_ACCESS_ROLE',
                    'role', v_add_access_role,
                    'domain', v_add_domain,
                    'status', 'SUCCESS'
                ));
            EXCEPTION
                WHEN OTHER THEN
                    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                        'action', 'GRANT_ADDITIONAL_ACCESS_ROLE',
                        'role', v_add_access_role,
                        'domain', v_add_domain,
                        'status', 'ERROR_OR_NOT_EXISTS',
                        'note', SQLERRM
                    ));
            END;
        END FOR;
    END IF;

    -- =========================================================================
    -- SET DEFAULT ROLE AND WAREHOUSE
    -- =========================================================================
    v_sql := 'ALTER USER ' || P_USER_NAME || ' SET DEFAULT_ROLE = ''' || v_functional_role || '''';
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'SET_DEFAULT_ROLE',
            'role', v_functional_role,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'SET_DEFAULT_ROLE',
                'role', v_functional_role,
                'status', 'ERROR',
                'note', SQLERRM
            ));
    END;
    
    v_sql := 'ALTER USER ' || P_USER_NAME || ' SET DEFAULT_WAREHOUSE = ''' || P_DEFAULT_WAREHOUSE || '''';
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'SET_DEFAULT_WAREHOUSE',
            'warehouse', P_DEFAULT_WAREHOUSE,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'SET_DEFAULT_WAREHOUSE',
                'warehouse', P_DEFAULT_WAREHOUSE,
                'status', 'ERROR',
                'note', SQLERRM
            ));
    END;

    -- =========================================================================
    -- Return Success
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'user_name', P_USER_NAME,
        'user_type', v_user_type,
        'environment', P_ENVIRONMENT,
        'capability_level', P_CAPABILITY_LEVEL,
        'functional_role', v_functional_role,
        'primary_domain', P_DOMAIN,
        'primary_access_role', v_access_role,
        'additional_domains', COALESCE(P_ADDITIONAL_DOMAINS, ARRAY_CONSTRUCT()),
        'default_warehouse', P_DEFAULT_WAREHOUSE,
        'actions', v_actions,
        'note', 'User configured. Privileges combined via SECONDARY_ROLES = ALL.'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'user_name', P_USER_NAME,
            'actions_attempted', v_actions
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Disable User
 * 
 * Purpose: Disables a user account (does not delete)
 * 
 * Parameters:
 *   P_USER_NAME - Username to disable
 *   P_REASON    - Reason for disabling (for audit)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_DISABLE_USER(
    P_USER_NAME VARCHAR,
    P_REASON VARCHAR DEFAULT 'Disabled via RBAC procedure'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    -- Check if user exists
    LET v_user_exists BOOLEAN := (
        SELECT COUNT(*) > 0
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME = UPPER(:P_USER_NAME)
          AND DELETED_ON IS NULL
    );
    
    IF NOT v_user_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User does not exist',
            'user_name', P_USER_NAME
        );
    END IF;
    
    -- Disable the user
    v_sql := 'ALTER USER ' || P_USER_NAME || ' SET DISABLED = TRUE';
    EXECUTE IMMEDIATE v_sql;
    
    -- Update comment with disable reason
    v_sql := 'ALTER USER ' || P_USER_NAME || ' SET COMMENT = ''DISABLED: ' || P_REASON || ' at ' || CURRENT_TIMESTAMP()::VARCHAR || '''';
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'user_name', P_USER_NAME,
        'action', 'DISABLED',
        'reason', P_REASON,
        'timestamp', CURRENT_TIMESTAMP()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'user_name', P_USER_NAME
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Rotate Service Account Key
 * 
 * Purpose: Rotates the RSA public key for a service account
 *          Supports zero-downtime rotation using RSA_PUBLIC_KEY_2
 * 
 * Parameters:
 *   P_ACCOUNT_NAME     - Service account name
 *   P_NEW_PUBLIC_KEY   - New RSA public key
 *   P_KEY_SLOT         - Which key slot to update: 1 (primary) or 2 (secondary)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_ROTATE_SERVICE_KEY(
    P_ACCOUNT_NAME VARCHAR,
    P_NEW_PUBLIC_KEY VARCHAR,
    P_KEY_SLOT INTEGER DEFAULT 2
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_user_type VARCHAR;
BEGIN
    -- Validate key slot
    IF P_KEY_SLOT NOT IN (1, 2) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid key slot. Must be 1 (primary) or 2 (secondary)'
        );
    END IF;
    
    -- Validate key
    IF P_NEW_PUBLIC_KEY IS NULL OR LENGTH(P_NEW_PUBLIC_KEY) < 100 THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid RSA public key'
        );
    END IF;
    
    -- Check if account exists and is a service account
    v_user_type := (
        SELECT TYPE
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME = UPPER(:P_ACCOUNT_NAME)
          AND DELETED_ON IS NULL
    );
    
    IF v_user_type IS NULL THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Account does not exist',
            'account_name', P_ACCOUNT_NAME
        );
    END IF;
    
    IF v_user_type NOT IN ('SERVICE', 'LEGACY_SERVICE') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Account is not a service account',
            'account_name', P_ACCOUNT_NAME,
            'account_type', v_user_type
        );
    END IF;
    
    -- Update the appropriate key slot
    IF P_KEY_SLOT = 1 THEN
        v_sql := 'ALTER USER ' || P_ACCOUNT_NAME || ' SET RSA_PUBLIC_KEY = ''' || P_NEW_PUBLIC_KEY || '''';
    ELSE
        v_sql := 'ALTER USER ' || P_ACCOUNT_NAME || ' SET RSA_PUBLIC_KEY_2 = ''' || P_NEW_PUBLIC_KEY || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'account_name', P_ACCOUNT_NAME,
        'key_slot_updated', P_KEY_SLOT,
        'rotation_steps', ARRAY_CONSTRUCT(
            '1. New key has been set in slot ' || P_KEY_SLOT::VARCHAR,
            '2. Update your application to use the new private key',
            '3. Test connectivity with the new key',
            '4. Once verified, you can remove the old key from the other slot'
        ),
        'timestamp', CURRENT_TIMESTAMP()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'account_name', P_ACCOUNT_NAME
        );
END;
$$;

-- Grant execute permissions
GRANT USAGE ON PROCEDURE RBAC_CREATE_SERVICE_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_CREATE_SERVICE_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_CONFIGURE_USER(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, ARRAY) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_DISABLE_USER(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_DISABLE_USER(VARCHAR, VARCHAR) TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_ROTATE_SERVICE_KEY(VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;
