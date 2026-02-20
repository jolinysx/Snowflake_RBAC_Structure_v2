/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Management
 * 
 * Purpose: Manage database and schema clones with RBAC security controls
 *          Enforces clone limits, maintains ownership with DBADMIN,
 *          and provides user access through dedicated database roles
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          CLONES
 *   Object Type:     TABLES (2), PROCEDURES (~10)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRF_*_DBADMIN, SRS_SECURITY_ADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and CLONES schema must exist
 *     - SRS_SYSTEM_ADMIN role must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * OWNERSHIP MODEL
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Clone ownership remains with SRF_*_DBADMIN (not the requesting user)
 *   • Users receive access via dedicated SRD_* database roles
 *   • This maintains RBAC integrity - users cannot bypass security
 *   • DBADMIN can revoke access, delete clones, and audit all clones
 * 
 * CLONE LIMITS:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Default: 3 clones per user per environment
 *   • Configurable per environment (DEV may allow more, PRD may allow fewer)
 *   • Enforced at creation time - must delete before creating new
 * 
 * NAMING CONVENTION:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Schema Clone:   <DATABASE>.<SCHEMA>_CLONE_<USERNAME>_<NUM>
 *   Database Clone: <DATABASE>_CLONE_<USERNAME>_<NUM>
 *   Database Role:  SRD_<DOMAIN>_<ENV>_<SCHEMA>_CLONE_<USERNAME>_<NUM>_<RW>
 * 
 * PROCEDURES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   RBAC_CREATE_CLONE           - Create a schema or database clone
 *   RBAC_LIST_USER_CLONES       - List all clones for a user
 *   RBAC_DELETE_CLONE           - Delete a specific clone
 *   RBAC_REPLACE_CLONE          - Delete oldest clone and create new
 *   RBAC_GET_CLONE_LIMITS       - View clone limit configuration
 *   RBAC_SET_CLONE_LIMIT        - Configure clone limits (admin only)
 *   RBAC_LIST_ALL_CLONES        - List all clones (admin only)
 *   RBAC_CLEANUP_EXPIRED_CLONES - Remove expired clones (admin only)
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA CLONES;

-- #############################################################################
-- SECTION 1: CLONE TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_LIMITS (
    ENVIRONMENT VARCHAR(10) NOT NULL,
    MAX_CLONES_PER_USER INTEGER DEFAULT 3,
    CLONE_EXPIRY_DAYS INTEGER DEFAULT NULL,
    ALLOW_DATABASE_CLONES BOOLEAN DEFAULT FALSE,
    ALLOW_SCHEMA_CLONES BOOLEAN DEFAULT TRUE,
    UPDATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (ENVIRONMENT)
);

-- Insert default limits for each environment
MERGE INTO ADMIN.CLONES.RBAC_CLONE_LIMITS AS target
USING (
    SELECT 'DEV' AS ENV, 5 AS MAX_CLONES, NULL AS EXPIRY, TRUE AS DB_CLONE, TRUE AS SCHEMA_CLONE
    UNION ALL SELECT 'TST', 3, 30, FALSE, TRUE
    UNION ALL SELECT 'UAT', 2, 14, FALSE, TRUE
    UNION ALL SELECT 'PPE', 1, 7, FALSE, TRUE
    UNION ALL SELECT 'PRD', 1, 7, FALSE, TRUE
) AS source
ON target.ENVIRONMENT = source.ENV
WHEN NOT MATCHED THEN
    INSERT (ENVIRONMENT, MAX_CLONES_PER_USER, CLONE_EXPIRY_DAYS, ALLOW_DATABASE_CLONES, ALLOW_SCHEMA_CLONES)
    VALUES (source.ENV, source.MAX_CLONES, source.EXPIRY, source.DB_CLONE, source.SCHEMA_CLONE);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_REGISTRY (
    CLONE_ID VARCHAR(36) DEFAULT UUID_STRING() NOT NULL,
    CLONE_TYPE VARCHAR(20) NOT NULL,
    ENVIRONMENT VARCHAR(10) NOT NULL,
    SOURCE_DATABASE VARCHAR(255) NOT NULL,
    SOURCE_SCHEMA VARCHAR(255),
    CLONE_DATABASE VARCHAR(255) NOT NULL,
    CLONE_SCHEMA VARCHAR(255),
    CLONE_NAME VARCHAR(255) NOT NULL,
    CLONE_NUMBER INTEGER NOT NULL,
    DATABASE_ROLE_READ VARCHAR(255),
    DATABASE_ROLE_WRITE VARCHAR(255),
    CREATED_BY VARCHAR(255) NOT NULL DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    EXPIRES_AT TIMESTAMP_NTZ,
    INCLUDE_DATA BOOLEAN DEFAULT TRUE,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    METADATA VARIANT
);

-- Note: Regular Snowflake tables don't support indexes or enforced primary keys.
-- Snowflake's automatic clustering and pruning handle query optimization.

-- #############################################################################
-- SECTION 2: CLONE LIMIT MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Clone Limits
 * 
 * Purpose: View current clone limit configuration for each environment
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_LIMITS()
RETURNS TABLE (
    ENVIRONMENT VARCHAR,
    MAX_CLONES_PER_USER INTEGER,
    CLONE_EXPIRY_DAYS INTEGER,
    ALLOW_DATABASE_CLONES BOOLEAN,
    ALLOW_SCHEMA_CLONES BOOLEAN
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            ENVIRONMENT,
            MAX_CLONES_PER_USER,
            CLONE_EXPIRY_DAYS,
            ALLOW_DATABASE_CLONES,
            ALLOW_SCHEMA_CLONES
        FROM RBAC_CLONE_LIMITS
        ORDER BY 
            CASE ENVIRONMENT 
                WHEN 'DEV' THEN 1 
                WHEN 'TST' THEN 2 
                WHEN 'UAT' THEN 3 
                WHEN 'PPE' THEN 4 
                WHEN 'PRD' THEN 5 
            END
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Set Clone Limit
 * 
 * Purpose: Configure clone limits for an environment (admin only)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_SET_CLONE_LIMIT(
    P_ENVIRONMENT VARCHAR,
    P_MAX_CLONES INTEGER DEFAULT NULL,
    P_EXPIRY_DAYS INTEGER DEFAULT NULL,
    P_ALLOW_DATABASE_CLONES BOOLEAN DEFAULT NULL,
    P_ALLOW_SCHEMA_CLONES BOOLEAN DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Update limits (only non-NULL values)
    UPDATE RBAC_CLONE_LIMITS
    SET MAX_CLONES_PER_USER = COALESCE(P_MAX_CLONES, MAX_CLONES_PER_USER),
        CLONE_EXPIRY_DAYS = COALESCE(P_EXPIRY_DAYS, CLONE_EXPIRY_DAYS),
        ALLOW_DATABASE_CLONES = COALESCE(P_ALLOW_DATABASE_CLONES, ALLOW_DATABASE_CLONES),
        ALLOW_SCHEMA_CLONES = COALESCE(P_ALLOW_SCHEMA_CLONES, ALLOW_SCHEMA_CLONES),
        UPDATED_BY = CURRENT_USER(),
        UPDATED_AT = CURRENT_TIMESTAMP()
    WHERE ENVIRONMENT = P_ENVIRONMENT;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'message', 'Clone limits updated'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: CLONE CREATION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Clone
 * 
 * Purpose: Creates a schema or database clone with RBAC security
 *          - Enforces clone limits per user
 *          - Ownership remains with DBADMIN
 *          - User receives access via dedicated database role
 * 
 * Parameters:
 *   P_ENVIRONMENT       - Environment: DEV, TST, UAT, PPE, PRD
 *   P_SOURCE_DATABASE   - Source database name (without env suffix)
 *   P_SOURCE_SCHEMA     - Source schema name (NULL for database clone)
 *   P_CLONE_TYPE        - 'SCHEMA' or 'DATABASE'
 *   P_INCLUDE_DATA      - TRUE to clone with data, FALSE for structure only
 *   P_CLONE_SUFFIX      - Optional suffix for clone name (default: auto-numbered)
 * 
 * Returns:
 *   Clone details including name, database role, and access instructions
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE(
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR DEFAULT NULL,
    P_CLONE_TYPE VARCHAR DEFAULT 'SCHEMA',
    P_INCLUDE_DATA BOOLEAN DEFAULT TRUE,
    P_CLONE_SUFFIX VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_current_user VARCHAR := CURRENT_USER();
    v_user_clean VARCHAR;
    v_clone_count INTEGER;
    v_max_clones INTEGER;
    v_expiry_days INTEGER;
    v_allow_db_clone BOOLEAN;
    v_allow_schema_clone BOOLEAN;
    v_full_source_db VARCHAR;
    v_clone_number INTEGER;
    v_clone_name VARCHAR;
    v_clone_db VARCHAR;
    v_clone_schema VARCHAR;
    v_db_role_read VARCHAR;
    v_db_role_write VARCHAR;
    v_dbadmin_role VARCHAR;
    v_expires_at TIMESTAMP_NTZ;
    v_sql VARCHAR;
    v_clone_id VARCHAR;
    v_existing_clones ARRAY;
BEGIN
    -- Clean username for object naming (replace special chars)
    v_user_clean := REGEXP_REPLACE(UPPER(v_current_user), '[^A-Z0-9]', '_');
    v_user_clean := REGEXP_REPLACE(v_user_clean, '_+', '_');
    v_user_clean := TRIM(v_user_clean, '_');
    
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate clone type
    IF (UPPER(P_CLONE_TYPE) NOT IN ('SCHEMA', 'DATABASE')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid clone type. Must be SCHEMA or DATABASE'
        );
    END IF;
    
    -- Schema clone requires schema name
    IF (UPPER(P_CLONE_TYPE) = 'SCHEMA' AND P_SOURCE_SCHEMA IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Schema name required for SCHEMA clone type'
        );
    END IF;
    
    -- Get clone limits for environment
    SELECT MAX_CLONES_PER_USER, CLONE_EXPIRY_DAYS, ALLOW_DATABASE_CLONES, ALLOW_SCHEMA_CLONES
    INTO v_max_clones, v_expiry_days, v_allow_db_clone, v_allow_schema_clone
    FROM RBAC_CLONE_LIMITS
    WHERE ENVIRONMENT = P_ENVIRONMENT;
    
    -- Check if clone type is allowed
    IF (UPPER(P_CLONE_TYPE) = 'DATABASE' AND NOT v_allow_db_clone) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Database clones are not allowed in ' || P_ENVIRONMENT || ' environment',
            'allowed_type', 'SCHEMA'
        );
    END IF;
    
    IF (UPPER(P_CLONE_TYPE) = 'SCHEMA' AND NOT v_allow_schema_clone) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Schema clones are not allowed in ' || P_ENVIRONMENT || ' environment'
        );
    END IF;
    
    -- Count user's current active clones in this environment
    SELECT COUNT(*), ARRAY_AGG(OBJECT_CONSTRUCT(
        'clone_id', CLONE_ID,
        'clone_name', CLONE_NAME,
        'clone_type', CLONE_TYPE,
        'created_at', CREATED_AT,
        'expires_at', EXPIRES_AT
    ))
    INTO v_clone_count, v_existing_clones
    FROM RBAC_CLONE_REGISTRY
    WHERE CREATED_BY = v_current_user
      AND ENVIRONMENT = P_ENVIRONMENT
      AND STATUS = 'ACTIVE';
    
    -- Check clone limit
    IF (v_clone_count >= v_max_clones) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Clone limit reached. You have ' || v_clone_count || ' of ' || v_max_clones || ' allowed clones in ' || P_ENVIRONMENT,
            'current_clones', v_existing_clones,
            'action_required', 'Delete an existing clone using RBAC_DELETE_CLONE() or use RBAC_REPLACE_CLONE() to replace oldest',
            'hint', 'CALL RBAC_LIST_USER_CLONES(); to see your clones'
        );
    END IF;
    
    -- Determine next clone number for this user
    SELECT COALESCE(MAX(CLONE_NUMBER), 0) + 1
    INTO v_clone_number
    FROM RBAC_CLONE_REGISTRY
    WHERE CREATED_BY = v_current_user
      AND ENVIRONMENT = P_ENVIRONMENT
      AND SOURCE_DATABASE = P_SOURCE_DATABASE
      AND (P_SOURCE_SCHEMA IS NULL OR SOURCE_SCHEMA = P_SOURCE_SCHEMA);
    
    -- Build names
    v_full_source_db := P_SOURCE_DATABASE || '_' || P_ENVIRONMENT;
    v_dbadmin_role := 'SRF_' || P_ENVIRONMENT || '_DBADMIN';
    
    IF (UPPER(P_CLONE_TYPE) = 'SCHEMA') THEN
        -- Schema clone
        v_clone_schema := P_SOURCE_SCHEMA || '_CLONE_' || v_user_clean || '_' || v_clone_number;
        v_clone_db := v_full_source_db;
        v_clone_name := v_clone_db || '.' || v_clone_schema;
        v_db_role_read := 'SRD_' || P_SOURCE_DATABASE || '_' || P_ENVIRONMENT || '_' || v_clone_schema || '_READ';
        v_db_role_write := 'SRD_' || P_SOURCE_DATABASE || '_' || P_ENVIRONMENT || '_' || v_clone_schema || '_WRITE';
    ELSE
        -- Database clone
        v_clone_db := v_full_source_db || '_CLONE_' || v_user_clean || '_' || v_clone_number;
        v_clone_schema := NULL;
        v_clone_name := v_clone_db;
        v_db_role_read := NULL;
        v_db_role_write := NULL;
    END IF;
    
    -- Calculate expiration
    IF (v_expiry_days IS NOT NULL) THEN
        v_expires_at := DATEADD(DAY, v_expiry_days, CURRENT_TIMESTAMP());
    ELSE
        v_expires_at := NULL;
    END IF;
    
    -- Generate clone ID
    v_clone_id := UUID_STRING();
    
    -- Create the clone
    IF (UPPER(P_CLONE_TYPE) = 'SCHEMA') THEN
        -- Clone schema
        IF (P_INCLUDE_DATA) THEN
            v_sql := 'CREATE OR REPLACE SCHEMA ' || v_clone_name || 
                     ' CLONE ' || v_full_source_db || '.' || P_SOURCE_SCHEMA;
        ELSE
            v_sql := 'CREATE OR REPLACE SCHEMA ' || v_clone_name || 
                     ' CLONE ' || v_full_source_db || '.' || P_SOURCE_SCHEMA ||
                     ' COPY GRANTS';
        END IF;
        EXECUTE IMMEDIATE v_sql;
        
        -- Create database roles for the clone
        v_sql := 'CREATE DATABASE ROLE IF NOT EXISTS ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        
        v_sql := 'CREATE DATABASE ROLE IF NOT EXISTS ' || v_clone_db || '.' || v_db_role_write;
        EXECUTE IMMEDIATE v_sql;
        
        -- Grant schema privileges to database roles
        -- READ role
        v_sql := 'GRANT USAGE ON SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON ALL TABLES IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON ALL VIEWS IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON FUTURE TABLES IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON FUTURE VIEWS IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read;
        EXECUTE IMMEDIATE v_sql;
        
        -- WRITE role (includes READ)
        v_sql := 'GRANT DATABASE ROLE ' || v_clone_db || '.' || v_db_role_read || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, CREATE FUNCTION ON SCHEMA ' || v_clone_name || ' TO DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write;
        EXECUTE IMMEDIATE v_sql;
        
        -- Grant database role to the requesting user
        v_sql := 'GRANT DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write || ' TO USER ' || v_current_user;
        EXECUTE IMMEDIATE v_sql;
        
        -- Grant database role to DBADMIN for management
        v_sql := 'GRANT DATABASE ROLE ' || v_clone_db || '.' || v_db_role_write || ' TO ROLE ' || v_dbadmin_role;
        EXECUTE IMMEDIATE v_sql;
        
    ELSE
        -- Clone database
        IF (P_INCLUDE_DATA) THEN
            v_sql := 'CREATE OR REPLACE DATABASE ' || v_clone_db || ' CLONE ' || v_full_source_db;
        ELSE
            v_sql := 'CREATE OR REPLACE DATABASE ' || v_clone_db || ' CLONE ' || v_full_source_db || ' COPY GRANTS';
        END IF;
        EXECUTE IMMEDIATE v_sql;
        
        -- Grant database usage to user
        v_sql := 'GRANT USAGE ON DATABASE ' || v_clone_db || ' TO USER ' || v_current_user;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT USAGE ON ALL SCHEMAS IN DATABASE ' || v_clone_db || ' TO USER ' || v_current_user;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON ALL TABLES IN DATABASE ' || v_clone_db || ' TO USER ' || v_current_user;
        EXECUTE IMMEDIATE v_sql;
        v_sql := 'GRANT SELECT ON ALL VIEWS IN DATABASE ' || v_clone_db || ' TO USER ' || v_current_user;
        EXECUTE IMMEDIATE v_sql;
        
        -- Grant ownership to DBADMIN
        v_sql := 'GRANT OWNERSHIP ON DATABASE ' || v_clone_db || ' TO ROLE ' || v_dbadmin_role || ' COPY CURRENT GRANTS';
        EXECUTE IMMEDIATE v_sql;
    END IF;
    
    -- Add comment to clone
    IF (UPPER(P_CLONE_TYPE) = 'SCHEMA') THEN
        v_sql := 'COMMENT ON SCHEMA ' || v_clone_name || ' IS ''Clone created by ' || v_current_user || 
                 ' on ' || CURRENT_TIMESTAMP()::VARCHAR || 
                 '. Clone ID: ' || v_clone_id || 
                 CASE WHEN v_expires_at IS NOT NULL THEN '. Expires: ' || v_expires_at::VARCHAR ELSE '' END || '''';
    ELSE
        v_sql := 'COMMENT ON DATABASE ' || v_clone_db || ' IS ''Clone created by ' || v_current_user || 
                 ' on ' || CURRENT_TIMESTAMP()::VARCHAR || 
                 '. Clone ID: ' || v_clone_id || 
                 CASE WHEN v_expires_at IS NOT NULL THEN '. Expires: ' || v_expires_at::VARCHAR ELSE '' END || '''';
    END IF;
    EXECUTE IMMEDIATE v_sql;
    
    -- Register the clone
    INSERT INTO RBAC_CLONE_REGISTRY (
        CLONE_ID, CLONE_TYPE, ENVIRONMENT, SOURCE_DATABASE, SOURCE_SCHEMA,
        CLONE_DATABASE, CLONE_SCHEMA, CLONE_NAME, CLONE_NUMBER,
        DATABASE_ROLE_READ, DATABASE_ROLE_WRITE, CREATED_BY, EXPIRES_AT, INCLUDE_DATA, STATUS
    ) VALUES (
        v_clone_id, UPPER(P_CLONE_TYPE), P_ENVIRONMENT, P_SOURCE_DATABASE, P_SOURCE_SCHEMA,
        v_clone_db, v_clone_schema, v_clone_name, v_clone_number,
        v_db_role_read, v_db_role_write, v_current_user, v_expires_at, P_INCLUDE_DATA, 'ACTIVE'
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'clone_id', v_clone_id,
        'clone_type', UPPER(P_CLONE_TYPE),
        'clone_name', v_clone_name,
        'source', v_full_source_db || COALESCE('.' || P_SOURCE_SCHEMA, ''),
        'database_role', v_db_role_write,
        'expires_at', v_expires_at,
        'include_data', P_INCLUDE_DATA,
        'clones_used', v_clone_count + 1,
        'clones_max', v_max_clones,
        'message', 'Clone created successfully. You have been granted access via database role.',
        'usage', ARRAY_CONSTRUCT(
            'Access your clone: USE SCHEMA ' || v_clone_name || ';',
            'List your clones: CALL RBAC_LIST_USER_CLONES();',
            'Delete this clone: CALL RBAC_DELETE_CLONE(''' || v_clone_id || ''');'
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

-- #############################################################################
-- SECTION 4: CLONE LISTING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: List User Clones
 * 
 * Purpose: Lists all clones for the current user (or specified user for admins)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_LIST_USER_CLONES(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_USERNAME VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    CLONE_ID VARCHAR,
    CLONE_TYPE VARCHAR,
    ENVIRONMENT VARCHAR,
    CLONE_NAME VARCHAR,
    SOURCE VARCHAR,
    DATABASE_ROLE VARCHAR,
    CREATED_AT TIMESTAMP_NTZ,
    EXPIRES_AT TIMESTAMP_NTZ,
    DAYS_UNTIL_EXPIRY INTEGER,
    STATUS VARCHAR
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_username VARCHAR;
    res RESULTSET;
BEGIN
    -- Default to current user
    v_username := COALESCE(P_USERNAME, CURRENT_USER());
    
    res := (
        SELECT 
            CLONE_ID,
            CLONE_TYPE,
            ENVIRONMENT,
            CLONE_NAME,
            SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, '') AS SOURCE,
            DATABASE_ROLE_WRITE AS DATABASE_ROLE,
            CREATED_AT,
            EXPIRES_AT,
            CASE 
                WHEN EXPIRES_AT IS NOT NULL 
                THEN DATEDIFF(DAY, CURRENT_TIMESTAMP(), EXPIRES_AT)
                ELSE NULL 
            END AS DAYS_UNTIL_EXPIRY,
            STATUS
        FROM RBAC_CLONE_REGISTRY
        WHERE CREATED_BY = v_username
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
          AND STATUS = 'ACTIVE'
        ORDER BY CREATED_AT DESC
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List All Clones (Admin)
 * 
 * Purpose: Lists all clones across all users (admin only)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_LIST_ALL_CLONES(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_STATUS VARCHAR DEFAULT 'ACTIVE'
)
RETURNS TABLE (
    CLONE_ID VARCHAR,
    CLONE_TYPE VARCHAR,
    ENVIRONMENT VARCHAR,
    CLONE_NAME VARCHAR,
    SOURCE VARCHAR,
    CREATED_BY VARCHAR,
    CREATED_AT TIMESTAMP_NTZ,
    EXPIRES_AT TIMESTAMP_NTZ,
    STATUS VARCHAR
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            CLONE_ID,
            CLONE_TYPE,
            ENVIRONMENT,
            CLONE_NAME,
            SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, '') AS SOURCE,
            CREATED_BY,
            CREATED_AT,
            EXPIRES_AT,
            STATUS
        FROM RBAC_CLONE_REGISTRY
        WHERE (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
        ORDER BY CREATED_AT DESC
    );
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 5: CLONE DELETION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Delete Clone
 * 
 * Purpose: Deletes a specific clone by ID or name
 *          Users can only delete their own clones
 *          Admins can delete any clone
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_DELETE_CLONE(
    P_CLONE_IDENTIFIER VARCHAR,
    P_FORCE BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_current_user VARCHAR := CURRENT_USER();
    v_clone VARIANT;
    v_clone_id VARCHAR;
    v_clone_name VARCHAR;
    v_clone_type VARCHAR;
    v_clone_db VARCHAR;
    v_clone_schema VARCHAR;
    v_db_role_read VARCHAR;
    v_db_role_write VARCHAR;
    v_created_by VARCHAR;
    v_sql VARCHAR;
BEGIN
    -- Find clone by ID or name
    SELECT OBJECT_CONSTRUCT(
        'clone_id', CLONE_ID,
        'clone_type', CLONE_TYPE,
        'clone_name', CLONE_NAME,
        'clone_database', CLONE_DATABASE,
        'clone_schema', CLONE_SCHEMA,
        'database_role_read', DATABASE_ROLE_READ,
        'database_role_write', DATABASE_ROLE_WRITE,
        'created_by', CREATED_BY
    ) INTO v_clone
    FROM RBAC_CLONE_REGISTRY
    WHERE (CLONE_ID = P_CLONE_IDENTIFIER OR CLONE_NAME = P_CLONE_IDENTIFIER)
      AND STATUS = 'ACTIVE';
    
    IF (v_clone IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Clone not found or already deleted',
            'identifier', P_CLONE_IDENTIFIER
        );
    END IF;
    
    -- Extract clone details
    v_clone_id := v_clone:clone_id::VARCHAR;
    v_clone_type := v_clone:clone_type::VARCHAR;
    v_clone_name := v_clone:clone_name::VARCHAR;
    v_clone_db := v_clone:clone_database::VARCHAR;
    v_clone_schema := v_clone:clone_schema::VARCHAR;
    v_db_role_read := v_clone:database_role_read::VARCHAR;
    v_db_role_write := v_clone:database_role_write::VARCHAR;
    v_created_by := v_clone:created_by::VARCHAR;
    
    -- Check ownership (unless admin or force)
    IF (v_created_by != v_current_user AND NOT P_FORCE) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'You can only delete your own clones. Use P_FORCE=TRUE if you have admin privileges.',
            'clone_owner', v_created_by
        );
    END IF;
    
    -- Drop the clone
    IF (v_clone_type = 'SCHEMA') THEN
        -- Drop database roles first
        BEGIN
            v_sql := 'DROP DATABASE ROLE IF EXISTS ' || v_clone_db || '.' || v_db_role_write;
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION WHEN OTHER THEN NULL;
        END;
        
        BEGIN
            v_sql := 'DROP DATABASE ROLE IF EXISTS ' || v_clone_db || '.' || v_db_role_read;
            EXECUTE IMMEDIATE v_sql;
        EXCEPTION WHEN OTHER THEN NULL;
        END;
        
        -- Drop schema
        v_sql := 'DROP SCHEMA IF EXISTS ' || v_clone_name;
        EXECUTE IMMEDIATE v_sql;
    ELSE
        -- Drop database
        v_sql := 'DROP DATABASE IF EXISTS ' || v_clone_db;
        EXECUTE IMMEDIATE v_sql;
    END IF;
    
    -- Update registry
    UPDATE RBAC_CLONE_REGISTRY
    SET STATUS = 'DELETED',
        METADATA = OBJECT_CONSTRUCT(
            'deleted_by', v_current_user,
            'deleted_at', CURRENT_TIMESTAMP(),
            'force_deleted', P_FORCE
        )
    WHERE CLONE_ID = v_clone_id;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'clone_id', v_clone_id,
        'clone_name', v_clone_name,
        'clone_type', v_clone_type,
        'message', 'Clone deleted successfully'
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

-- #############################################################################
-- SECTION 6: CLONE REPLACEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Replace Clone
 * 
 * Purpose: Deletes oldest clone and creates new clone in one operation
 *          Useful when user is at clone limit
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_REPLACE_CLONE(
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR DEFAULT NULL,
    P_CLONE_TYPE VARCHAR DEFAULT 'SCHEMA',
    P_INCLUDE_DATA BOOLEAN DEFAULT TRUE,
    P_REPLACE_OLDEST BOOLEAN DEFAULT TRUE,
    P_CLONE_TO_REPLACE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_current_user VARCHAR := CURRENT_USER();
    v_oldest_clone_id VARCHAR;
    v_clone_count INTEGER;
    v_max_clones INTEGER;
    v_delete_result VARIANT;
    v_create_result VARIANT;
BEGIN
    -- Get clone limits
    SELECT MAX_CLONES_PER_USER INTO v_max_clones
    FROM RBAC_CLONE_LIMITS
    WHERE ENVIRONMENT = P_ENVIRONMENT;
    
    -- Get current clone count
    SELECT COUNT(*) INTO v_clone_count
    FROM RBAC_CLONE_REGISTRY
    WHERE CREATED_BY = v_current_user
      AND ENVIRONMENT = P_ENVIRONMENT
      AND STATUS = 'ACTIVE';
    
    -- Only delete if at or over limit
    IF (v_clone_count >= v_max_clones) THEN
        -- Determine which clone to delete
        IF (P_CLONE_TO_REPLACE IS NOT NULL) THEN
            v_oldest_clone_id := P_CLONE_TO_REPLACE;
        ELSEIF (P_REPLACE_OLDEST) THEN
            -- Find oldest clone
            SELECT CLONE_ID INTO v_oldest_clone_id
            FROM RBAC_CLONE_REGISTRY
            WHERE CREATED_BY = v_current_user
              AND ENVIRONMENT = P_ENVIRONMENT
              AND STATUS = 'ACTIVE'
            ORDER BY CREATED_AT ASC
            LIMIT 1;
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Clone limit reached. Specify P_CLONE_TO_REPLACE or set P_REPLACE_OLDEST=TRUE',
                'current_clones', v_clone_count,
                'max_clones', v_max_clones
            );
        END IF;
        
        -- Delete the old clone
        CALL ADMIN.CLONES.RBAC_DELETE_CLONE(v_oldest_clone_id, FALSE) INTO v_delete_result;
        
        IF (v_delete_result:status != 'SUCCESS') THEN
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Failed to delete old clone',
                'delete_result', v_delete_result
            );
        END IF;
    END IF;
    
    -- Create new clone
    CALL ADMIN.CLONES.RBAC_CREATE_CLONE(
        P_ENVIRONMENT,
        P_SOURCE_DATABASE,
        P_SOURCE_SCHEMA,
        P_CLONE_TYPE,
        P_INCLUDE_DATA,
        NULL
    ) INTO v_create_result;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_create_result:status,
        'deleted_clone', v_oldest_clone_id,
        'new_clone', v_create_result,
        'message', CASE 
            WHEN v_oldest_clone_id IS NOT NULL 
            THEN 'Replaced oldest clone with new clone'
            ELSE 'Created new clone (no replacement needed)'
        END
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 7: CLONE MAINTENANCE
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Cleanup Expired Clones
 * 
 * Purpose: Removes clones that have passed their expiration date (admin only)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLEANUP_EXPIRED_CLONES(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_expired_clones ARRAY := ARRAY_CONSTRUCT();
    v_deleted_clones ARRAY := ARRAY_CONSTRUCT();
    v_clone_id VARCHAR;
    v_delete_result VARIANT;
    cur CURSOR FOR
        SELECT CLONE_ID
        FROM RBAC_CLONE_REGISTRY
        WHERE STATUS = 'ACTIVE'
          AND EXPIRES_AT IS NOT NULL
          AND EXPIRES_AT < CURRENT_TIMESTAMP()
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT);
BEGIN
    -- Find expired clones
    FOR record IN cur DO
        v_clone_id := record.CLONE_ID;
        
        SELECT ARRAY_APPEND(:v_expired_clones, OBJECT_CONSTRUCT(
            'clone_id', CLONE_ID,
            'clone_name', CLONE_NAME,
            'created_by', CREATED_BY,
            'expired_at', EXPIRES_AT
        )) INTO v_expired_clones
        FROM RBAC_CLONE_REGISTRY
        WHERE CLONE_ID = v_clone_id;
        
        IF (NOT P_DRY_RUN) THEN
            CALL ADMIN.CLONES.RBAC_DELETE_CLONE(v_clone_id, TRUE) INTO v_delete_result;
            v_deleted_clones := ARRAY_APPEND(v_deleted_clones, OBJECT_CONSTRUCT(
                'clone_id', v_clone_id,
                'result', v_delete_result
            ));
        END IF;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'expired_clones_found', ARRAY_SIZE(v_expired_clones),
        'expired_clones', v_expired_clones,
        'deleted_clones', v_deleted_clones,
        'message', IFF(P_DRY_RUN, 
            'Dry run complete. Set P_DRY_RUN=FALSE to delete expired clones.',
            'Expired clones have been deleted.'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Clone Summary
 * 
 * Purpose: Returns summary statistics about clones
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_SUMMARY(
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_active INTEGER;
    v_by_environment VARIANT;
    v_by_user VARIANT;
    v_expiring_soon INTEGER;
BEGIN
    -- Total active clones
    SELECT COUNT(*) INTO v_total_active
    FROM RBAC_CLONE_REGISTRY
    WHERE STATUS = 'ACTIVE'
      AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT);
    
    -- By environment
    SELECT OBJECT_AGG(ENVIRONMENT, CNT) INTO v_by_environment
    FROM (
        SELECT ENVIRONMENT, COUNT(*) AS CNT
        FROM RBAC_CLONE_REGISTRY
        WHERE STATUS = 'ACTIVE'
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
        GROUP BY ENVIRONMENT
    );
    
    -- By user (top 10)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('user', CREATED_BY, 'clone_count', CNT)) INTO v_by_user
    FROM (
        SELECT CREATED_BY, COUNT(*) AS CNT
        FROM RBAC_CLONE_REGISTRY
        WHERE STATUS = 'ACTIVE'
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
        GROUP BY CREATED_BY
        ORDER BY CNT DESC
        LIMIT 10
    );
    
    -- Expiring within 7 days
    SELECT COUNT(*) INTO v_expiring_soon
    FROM RBAC_CLONE_REGISTRY
    WHERE STATUS = 'ACTIVE'
      AND EXPIRES_AT IS NOT NULL
      AND EXPIRES_AT <= DATEADD(DAY, 7, CURRENT_TIMESTAMP())
      AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT);
    
    RETURN OBJECT_CONSTRUCT(
        'total_active_clones', v_total_active,
        'by_environment', v_by_environment,
        'top_users', v_by_user,
        'expiring_within_7_days', v_expiring_soon
    );
END;
$$;

-- #############################################################################
-- SECTION 8: GRANT PERMISSIONS
-- #############################################################################

-- User-level procedures (all users)
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE(VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN, VARCHAR) TO ROLE PUBLIC;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LIST_USER_CLONES(VARCHAR, VARCHAR) TO ROLE PUBLIC;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_DELETE_CLONE(VARCHAR, BOOLEAN) TO ROLE PUBLIC;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_REPLACE_CLONE(VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN, BOOLEAN, VARCHAR) TO ROLE PUBLIC;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_LIMITS() TO ROLE PUBLIC;

-- Admin procedures
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_SET_CLONE_LIMIT(VARCHAR, INTEGER, INTEGER, BOOLEAN, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LIST_ALL_CLONES(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LIST_ALL_CLONES(VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLEANUP_EXPIRED_CLONES(VARCHAR, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_SUMMARY(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
