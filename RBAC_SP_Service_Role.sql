/*******************************************************************************
 * RBAC STORED PROCEDURE: Service Role Management
 * 
 * Purpose: Creates and manages wrapper roles (SRW_*) for service accounts
 *          that require a single role combining capability and data access
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     FUNCTIONS (2), PROCEDURES (4)
 *   Object Names:    
 *     - ADMIN.RBAC.RBAC_IS_SERVICE_ACCOUNT (function)
 *     - ADMIN.RBAC.RBAC_IS_PERSON_ACCOUNT (function)
 *     - ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE
 *     - ADMIN.RBAC.RBAC_ADD_ACCESS_TO_SERVICE_ROLE
 *     - ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT
 *     - ADMIN.RBAC.RBAC_REVOKE_SERVICE_ACCOUNT
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - SRS_SYSTEM_ADMIN, SRS_SECURITY_ADMIN roles must exist
 *     - SNOWFLAKE.ACCOUNT_USAGE.USERS access required
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SERVICE ACCOUNT MODEL
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Service accounts include:
 *     - TYPE = 'SERVICE' (new service accounts)
 *     - TYPE = 'LEGACY_SERVICE' (legacy service accounts)
 * 
 *   Wrapper roles combine:
 *     - Functional role (SRF_*) - capability
 *     - Access role(s) (SRA_*) - data access
 * 
 *   Naming Convention: SRW_<ENV>_<DOMAIN>_<CAPABILITY>
 *     Example: SRW_PRD_HR_ANALYST (Production HR Analyst service role)
 * 
 *   Restrictions:
 *     - SRW_* roles can ONLY be granted to SERVICE or LEGACY_SERVICE accounts
 *     - SRF_* and SRA_* roles can ONLY be granted to PERSON accounts
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * USAGE EXAMPLES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   USE ROLE SRS_SECURITY_ADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE('PRD', 'HR', 'ANALYST', 'Power BI HR reporting');
 *   CALL ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT('SVC_POWERBI_HR', 'PRD', 'HR', 'ANALYST', TRUE);
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- FUNCTION: ADMIN.RBAC.RBAC_IS_SERVICE_ACCOUNT
-- =============================================================================

CREATE OR REPLACE FUNCTION ADMIN.RBAC.RBAC_IS_SERVICE_ACCOUNT(P_USER_NAME VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
AS
$$
    SELECT COUNT(*) > 0
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = P_USER_NAME
      AND DELETED_ON IS NULL
      AND TYPE IN ('SERVICE', 'LEGACY_SERVICE')
$$;

-- =============================================================================
-- FUNCTION: ADMIN.RBAC.RBAC_IS_PERSON_ACCOUNT
-- =============================================================================

CREATE OR REPLACE FUNCTION ADMIN.RBAC.RBAC_IS_PERSON_ACCOUNT(P_USER_NAME VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
AS
$$
    SELECT COUNT(*) > 0
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = P_USER_NAME
      AND DELETED_ON IS NULL
      AND (TYPE = 'PERSON' OR TYPE IS NULL)
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE(
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_COMMENT VARCHAR DEFAULT 'Service account wrapper role'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_functional_role VARCHAR;
    v_access_role VARCHAR;
    v_system_admin_role VARCHAR := 'SRS_SYSTEM_ADMIN';
    v_sql VARCHAR;
    v_access_role_exists BOOLEAN;
BEGIN
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    IF (P_CAPABILITY_LEVEL NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid capability level. Must be one of: END_USER, ANALYST, DEVELOPER, TEAM_LEADER, DATA_SCIENTIST, DBADMIN'
        );
    END IF;
    
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_' || P_CAPABILITY_LEVEL;
    v_functional_role := 'SRF_' || P_ENVIRONMENT || '_' || P_CAPABILITY_LEVEL;
    v_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_ACCESS';
    
    v_access_role_exists := (
        SELECT COUNT(*) > 0
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE NAME = :v_access_role AND DELETED_ON IS NULL
    );
    
    IF (NOT v_access_role_exists) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Access role does not exist. Create it first using ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE.',
            'access_role', v_access_role
        );
    END IF;
    
    v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_service_role || ' COMMENT = ''' || P_COMMENT || ' (Service wrapper role)''';
    EXECUTE IMMEDIATE v_sql;
    
    v_sql := 'GRANT ROLE ' || v_functional_role || ' TO ROLE ' || v_service_role;
    EXECUTE IMMEDIATE v_sql;
    
    v_sql := 'GRANT ROLE ' || v_access_role || ' TO ROLE ' || v_service_role;
    EXECUTE IMMEDIATE v_sql;
    
    v_sql := 'GRANT ROLE ' || v_service_role || ' TO ROLE ' || v_system_admin_role;
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN_NAME,
        'capability', P_CAPABILITY_LEVEL,
        'service_role', v_service_role,
        'inherits_from', ARRAY_CONSTRUCT(v_functional_role, v_access_role),
        'comment', P_COMMENT,
        'message', 'Service role created. Assign to service accounts using ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT.',
        'restriction', 'This role can ONLY be granted to SERVICE or LEGACY_SERVICE accounts'
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE, 'service_role', v_service_role);
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_ADD_ACCESS_TO_SERVICE_ROLE
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_ADD_ACCESS_TO_SERVICE_ROLE(
    P_ENVIRONMENT VARCHAR,
    P_SERVICE_DOMAIN VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_ADDITIONAL_DOMAIN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_additional_access_role VARCHAR;
    v_sql VARCHAR;
BEGIN
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_SERVICE_DOMAIN) || '_' || P_CAPABILITY_LEVEL;
    v_additional_access_role := 'SRA_' || P_ENVIRONMENT || '_' || UPPER(P_ADDITIONAL_DOMAIN) || '_ACCESS';
    
    LET v_service_role_exists BOOLEAN := (
        SELECT COUNT(*) > 0 FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE NAME = :v_service_role AND DELETED_ON IS NULL
    );
    
    IF NOT v_service_role_exists THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Service role does not exist.', 'service_role', v_service_role);
    END IF;
    
    v_access_role_exists := (
        SELECT COUNT(*) > 0 FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE NAME = :v_additional_access_role AND DELETED_ON IS NULL
    );
    
    IF (NOT v_access_role_exists) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Additional access role does not exist.', 'access_role', v_additional_access_role);
    END IF;
    
    v_sql := 'GRANT ROLE ' || v_additional_access_role || ' TO ROLE ' || v_service_role;
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT('status', 'SUCCESS', 'service_role', v_service_role, 'additional_access_added', v_additional_access_role);
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT(
    P_SERVICE_ACCOUNT VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_SET_AS_DEFAULT BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_is_service_account BOOLEAN;
    v_sql VARCHAR;
BEGIN
    v_is_service_account := (
        SELECT COUNT(*) > 0 FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME = :P_SERVICE_ACCOUNT AND DELETED_ON IS NULL AND TYPE IN ('SERVICE', 'LEGACY_SERVICE')
    );
    
    IF NOT v_is_service_account THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User is not a service account. SRW_* roles can ONLY be granted to SERVICE or LEGACY_SERVICE accounts.',
            'user', P_SERVICE_ACCOUNT,
            'hint', 'For human users, use ADMIN.RBAC.RBAC_GRANT_USER_ACCESS with SRF_* and SRA_* roles instead.'
        );
    END IF;
    
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_' || P_CAPABILITY_LEVEL;
    
    LET v_role_exists BOOLEAN := (
        SELECT COUNT(*) > 0 FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE NAME = :v_service_role AND DELETED_ON IS NULL
    );
    
    IF NOT v_role_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Service role does not exist. Create it first using ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE.',
            'service_role', v_service_role
        );
    END IF;
    
    v_sql := 'GRANT ROLE ' || v_service_role || ' TO USER ' || P_SERVICE_ACCOUNT;
    EXECUTE IMMEDIATE v_sql;
    
    IF P_SET_AS_DEFAULT THEN
        v_sql := 'ALTER USER ' || P_SERVICE_ACCOUNT || ' SET DEFAULT_ROLE = ''' || v_service_role || '''';
        EXECUTE IMMEDIATE v_sql;
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'service_account', P_SERVICE_ACCOUNT,
        'service_role', v_service_role,
        'set_as_default', P_SET_AS_DEFAULT,
        'message', 'Service account configured successfully.'
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE, 'service_account', P_SERVICE_ACCOUNT);
END;
$$;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_REVOKE_SERVICE_ACCOUNT
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_REVOKE_SERVICE_ACCOUNT(
    P_SERVICE_ACCOUNT VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN_NAME VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_sql VARCHAR;
BEGIN
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN_NAME) || '_' || P_CAPABILITY_LEVEL;
    
    v_sql := 'REVOKE ROLE ' || v_service_role || ' FROM USER ' || P_SERVICE_ACCOUNT;
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT('status', 'SUCCESS', 'service_account', P_SERVICE_ACCOUNT, 'service_role_revoked', v_service_role);
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE, 'service_account', P_SERVICE_ACCOUNT);
END;
$$;

-- =============================================================================
-- GRANTS: Execution Permissions
-- =============================================================================

GRANT USAGE ON FUNCTION ADMIN.RBAC.RBAC_IS_SERVICE_ACCOUNT(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON FUNCTION ADMIN.RBAC.RBAC_IS_PERSON_ACCOUNT(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_ADD_ACCESS_TO_SERVICE_ROLE(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_REVOKE_SERVICE_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- =============================================================================
-- VERIFICATION
-- =============================================================================
-- After deployment, verify:
--   SHOW PROCEDURES LIKE 'RBAC_%SERVICE%' IN SCHEMA ADMIN.RBAC;
--   SHOW FUNCTIONS LIKE 'RBAC_IS_%' IN SCHEMA ADMIN.RBAC;
-- =============================================================================
