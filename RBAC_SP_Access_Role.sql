/*******************************************************************************
 * RBAC STORED PROCEDURE: Access Role Management
 * 
 * Purpose: Creates and manages Access Roles (SRA_*) for domain/team data access
 *          Access roles hold database roles and provide data access segregation
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURES (4)
 *   Object Names:    
 *     - ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE
 *     - ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE
 *     - ADMIN.RBAC.RBAC_GRANT_USER_ACCESS
 *     - ADMIN.RBAC.RBAC_REVOKE_USER_ACCESS
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedures)
 *   Execution Role:  SRS_SECURITY_ADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database must exist
 *     - ADMIN.RBAC schema must exist
 *     - SRS_SYSTEM_ADMIN, SRS_SECURITY_ADMIN roles must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * USAGE EXAMPLES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   -- Create an access role
 *   USE ROLE SRS_SECURITY_ADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE('DEV', 'HR', 'HR team data access');
 *   
 *   -- Link schema to access role
 *   CALL ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE('DEV', 'HR', 'HR', 'EMPLOYEES', 'WRITE');
 *   
 *   -- Grant user access
 *   CALL ADMIN.RBAC.RBAC_GRANT_USER_ACCESS('john_doe', 'DEV', 'HR', 'DEVELOPER');
 * 
 ******************************************************************************/


-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE(
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_COMMENT VARCHAR DEFAULT 'Access role for domain data'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_role VARCHAR;
    v_security_admin_role VARCHAR := 'SRS_SECURITY_ADMIN';
    v_system_admin_role VARCHAR := 'SRS_SYSTEM_ADMIN';
    v_sql VARCHAR;
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate domain name
    IF (P_DOMAIN_NAME IS NULL OR P_DOMAIN_NAME = '') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Domain name is required'
        );
    END IF;
    
    -- Derive access role name
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_ACCESS';
    
    -- Create the access role
    v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_access_role ||
             ' COMMENT = ''' || P_COMMENT || '''';
    EXECUTE IMMEDIATE v_sql;
    
    -- Grant access role to SRS_SYSTEM_ADMIN for administrative access
    v_sql := 'GRANT ROLE ' || v_access_role || ' TO ROLE ' || v_system_admin_role;
    EXECUTE IMMEDIATE v_sql;
    
    -- Return success
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN_NAME,
        'access_role', v_access_role,
        'comment', P_COMMENT,
        'message', 'Access role created. Use ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE to add database roles.'
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'access_role', v_access_role
        );
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE(
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_ACCESS_LEVEL VARCHAR DEFAULT 'READ'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_role VARCHAR;
    v_full_db_name VARCHAR;
    v_db_role VARCHAR;
    v_is_dev BOOLEAN;
    v_sql VARCHAR;
    v_role_check_result RESULTSET;
    v_access_role_exists BOOLEAN := FALSE;
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate access level
    IF (P_ACCESS_LEVEL NOT IN ('READ', 'WRITE')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid access level. Must be READ or WRITE'
        );
    END IF;
    
    -- Check if WRITE is requested for non-DEV environment
    v_is_dev := (P_ENVIRONMENT = 'DEV');
    IF ((NOT v_is_dev) AND P_ACCESS_LEVEL = 'WRITE') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'WRITE access is only available in DEV environment. Use READ for non-DEV.',
            'environment', P_ENVIRONMENT
        );
    END IF;
    
    -- Derive names
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_ACCESS';
    v_full_db_name := P_DATABASE_NAME || '_' || P_ENVIRONMENT;
    v_db_role := 'SRD_' || v_full_db_name || '_' || P_SCHEMA_NAME || '_' || P_ACCESS_LEVEL;
    
    -- Verify access role exists (FIXED: Using SHOW ROLES for real-time validation instead of ACCOUNT_USAGE)
    v_sql := 'SHOW ROLES LIKE ''' || v_access_role || '''';
    v_role_check_result := (EXECUTE IMMEDIATE :v_sql);
    LET c1 CURSOR FOR v_role_check_result;
    FOR record IN c1 DO
        v_access_role_exists := TRUE;
    END FOR;
    
    IF (NOT v_access_role_exists) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Access role does not exist. Create it first using ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE.',
            'access_role', v_access_role
        );
    END IF;
    
    -- Grant database role to access role
    v_sql := 'GRANT DATABASE ROLE ' || v_full_db_name || '.' || v_db_role || 
             ' TO ROLE ' || v_access_role;
    EXECUTE IMMEDIATE v_sql;
    
    -- Return success
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN_NAME,
        'access_role', v_access_role,
        'database', v_full_db_name,
        'schema', P_SCHEMA_NAME,
        'database_role', v_db_role,
        'access_level', P_ACCESS_LEVEL,
        'sql_executed', v_sql
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'access_role', v_access_role,
            'database_role', v_db_role
        );
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_GRANT_USER_ACCESS
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_GRANT_USER_ACCESS(
    P_USER_NAME VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_FUNCTIONAL_ROLE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_role VARCHAR;
    v_functional_role VARCHAR;
    v_grants_made ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
    v_is_service_account BOOLEAN;
BEGIN
    -- =========================================================================
    -- VALIDATION: Check if user is a service account
    -- SRF_* and SRA_* roles can ONLY be granted to PERSON accounts
    -- =========================================================================
    SELECT COUNT(*) > 0 INTO :v_is_service_account
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = :P_USER_NAME
      AND DELETED_ON IS NULL
      AND TYPE IN ('SERVICE', 'LEGACY_SERVICE');
    
    IF (v_is_service_account) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User is a service account. SRF_* and SRA_* roles can ONLY be granted to PERSON accounts.',
            'user', P_USER_NAME,
            'hint', 'For service accounts, use ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT with SRW_* wrapper roles instead.'
        );
    END IF;
    
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate functional role if provided
    IF (P_FUNCTIONAL_ROLE IS NOT NULL AND 
       P_FUNCTIONAL_ROLE NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid functional role. Must be one of: END_USER, ANALYST, DEVELOPER, TEAM_LEADER, DATA_SCIENTIST, DBADMIN'
        );
    END IF;
    
    -- Derive role names
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_ACCESS';
    
    -- Grant functional role if specified
    IF (P_FUNCTIONAL_ROLE IS NOT NULL) THEN
        v_functional_role := 'SRF_' || P_ENVIRONMENT || '_' || P_FUNCTIONAL_ROLE;
        v_sql := 'GRANT ROLE ' || v_functional_role || ' TO USER ' || P_USER_NAME;
        EXECUTE IMMEDIATE v_sql;
        v_grants_made := ARRAY_APPEND(v_grants_made, OBJECT_CONSTRUCT(
            'role_type', 'FUNCTIONAL',
            'role', v_functional_role
        ));
    END IF;
    
    -- Grant access role
    v_sql := 'GRANT ROLE ' || v_access_role || ' TO USER ' || P_USER_NAME;
    EXECUTE IMMEDIATE v_sql;
    v_grants_made := ARRAY_APPEND(v_grants_made, OBJECT_CONSTRUCT(
        'role_type', 'ACCESS',
        'role', v_access_role
    ));
    
    -- Return success
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'user', P_USER_NAME,
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN_NAME,
        'grants_made', v_grants_made,
        'message', 'User access configured. User will have combined privileges via SECONDARY_ROLES.'
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'user', P_USER_NAME
        );
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_REVOKE_USER_ACCESS
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_REVOKE_USER_ACCESS(
    P_USER_NAME VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_REVOKE_FUNCTIONAL BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_role VARCHAR;
    v_revokes_made ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Derive access role name
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_ACCESS';
    
    -- Revoke access role
    v_sql := 'REVOKE ROLE ' || v_access_role || ' FROM USER ' || P_USER_NAME;
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_revokes_made := ARRAY_APPEND(v_revokes_made, OBJECT_CONSTRUCT(
            'role_type', 'ACCESS',
            'role', v_access_role,
            'status', 'REVOKED'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_revokes_made := ARRAY_APPEND(v_revokes_made, OBJECT_CONSTRUCT(
                'role_type', 'ACCESS',
                'role', v_access_role,
                'status', 'NOT_GRANTED_OR_ERROR',
                'error', SQLERRM
            ));
    END;
    
    -- Return success
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'user', P_USER_NAME,
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN_NAME,
        'revokes_made', v_revokes_made
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'user', P_USER_NAME
        );
END;
$$;

-- =============================================================================
-- GRANTS: Procedure Execution Permissions
-- =============================================================================

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_GRANT_USER_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_REVOKE_USER_ACCESS(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;

-- =============================================================================
-- VERIFICATION
-- =============================================================================
-- After deployment, verify the procedures exist:
--   SHOW PROCEDURES LIKE 'RBAC_%ACCESS%' IN SCHEMA ADMIN.RBAC;
-- =============================================================================
