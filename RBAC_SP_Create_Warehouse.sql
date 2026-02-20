/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Warehouse
 * 
 * Purpose: Creates an environment warehouse with proper RBAC configuration
 *          and grants appropriate access to functional roles
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURE
 *   Object Name:     ADMIN.RBAC.RBAC_CREATE_WAREHOUSE
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedure)
 *   Execution Role:  SRF_<ENV>_DBADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database must exist
 *     - ADMIN.RBAC schema must exist
 *     - SRF_*_DBADMIN roles must exist
 *     - SRF_*_END_USER roles must exist
 *     - SRS_DEVOPS role must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PARAMETERS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   P_ENVIRONMENT       - Environment code: DEV, TST, UAT, PPE, PRD
 *   P_WAREHOUSE_SIZE    - Warehouse size: XSMALL, SMALL, MEDIUM, LARGE, etc.
 *   P_AUTO_SUSPEND      - Auto suspend time in seconds (default: 60)
 *   P_WAREHOUSE_SUFFIX  - Optional suffix for additional warehouses (default: NULL)
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * USAGE EXAMPLES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   -- Create standard environment warehouse
 *   USE ROLE SRF_DEV_DBADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_WAREHOUSE('DEV', 'XSMALL', 60, NULL);
 *   
 *   -- Create additional warehouse with suffix
 *   USE ROLE SRF_PRD_DBADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_WAREHOUSE('PRD', 'LARGE', 120, 'ETL');
 *   -- Creates: PRD_ETL_WH
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
-- The following statements set the context for deploying this procedure.
-- Run this entire file as SRS_SYSTEM_ADMIN to deploy the procedure.
-- =============================================================================

USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_WAREHOUSE
-- =============================================================================


SHOW WAREHOUSES;

  CALL RBAC_CREATE_WAREHOUSE('DEV', 'XSMALL', 60, 'TEST');



CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(
    P_ENVIRONMENT VARCHAR,
    P_WAREHOUSE_SIZE VARCHAR DEFAULT 'XSMALL',
    P_AUTO_SUSPEND INTEGER DEFAULT 60,
    P_WAREHOUSE_SUFFIX VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_warehouse_name VARCHAR;
    v_dbadmin_role VARCHAR;
    v_end_user_role VARCHAR;
    v_devops_role VARCHAR := 'SRS_DEVOPS';
    v_is_dev BOOLEAN;
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Validate warehouse size
    IF (P_WAREHOUSE_SIZE NOT IN ('XSMALL', 'SMALL', 'MEDIUM', 'LARGE', 'XLARGE', 'XXLARGE', 'XXXLARGE', 'X4LARGE', 'X5LARGE', 'X6LARGE')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid warehouse size'
        );
    END IF;
    
    -- Derive names
    IF (P_WAREHOUSE_SUFFIX IS NOT NULL AND P_WAREHOUSE_SUFFIX != '') THEN
        v_warehouse_name := P_ENVIRONMENT || '_' || P_WAREHOUSE_SUFFIX || '_WH';
    ELSE
        v_warehouse_name := P_ENVIRONMENT || '_WH';
    END IF;
    
    v_dbadmin_role := 'SRF_' || P_ENVIRONMENT || '_DBADMIN';
    v_end_user_role := 'SRF_' || P_ENVIRONMENT || '_END_USER';
    v_is_dev := (P_ENVIRONMENT = 'DEV');
    
    -- =========================================================================
    -- STEP 1: Create Warehouse
    -- =========================================================================
    v_sql := 'CREATE WAREHOUSE IF NOT EXISTS ' || v_warehouse_name ||
             ' WAREHOUSE_SIZE = ''' || P_WAREHOUSE_SIZE || '''' ||
             ' AUTO_SUSPEND = ' || P_AUTO_SUSPEND ||
             ' AUTO_RESUME = TRUE' ||
             ' INITIALLY_SUSPENDED = TRUE' ||
             ' COMMENT = ''Warehouse for ' || P_ENVIRONMENT || ' environment''';
    
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'CREATE_WAREHOUSE',
        'sql', v_sql,
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- STEP 2: Grant USAGE to Functional Roles
    -- All functional users get USAGE (via END_USER which inherits up)
    -- =========================================================================
    v_sql := 'GRANT USAGE ON WAREHOUSE ' || v_warehouse_name || ' TO ROLE ' || v_end_user_role;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_USAGE_TO_ENDUSER',
        'sql', v_sql,
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- STEP 3: Grant OPERATE and MONITOR to DBADMIN
    -- =========================================================================
    v_sql := 'GRANT OPERATE ON WAREHOUSE ' || v_warehouse_name || ' TO ROLE ' || v_dbadmin_role;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_OPERATE_TO_DBADMIN',
        'sql', v_sql,
        'status', 'SUCCESS'
    ));
    
    v_sql := 'GRANT MONITOR ON WAREHOUSE ' || v_warehouse_name || ' TO ROLE ' || v_dbadmin_role;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_MONITOR_TO_DBADMIN',
        'sql', v_sql,
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- STEP 4: Grant USAGE to SRS_DEVOPS (for non-DEV environments)
    -- DevOps needs warehouse access to deploy objects
    -- =========================================================================
    IF (NOT v_is_dev) THEN
        v_sql := 'GRANT USAGE ON WAREHOUSE ' || v_warehouse_name || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_USAGE_TO_DEVOPS',
            'sql', v_sql,
            'status', 'SUCCESS'
        ));
    END IF;
    
    -- =========================================================================
    -- Return Success Result
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'warehouse_name', v_warehouse_name,
        'warehouse_size', P_WAREHOUSE_SIZE,
        'auto_suspend_seconds', P_AUTO_SUSPEND,
        'owner', v_dbadmin_role,
        'usage_granted_to', ARRAY_CONSTRUCT(
            v_end_user_role,
            IFF(NOT v_is_dev, v_devops_role, NULL)
        ),
        'actions', v_actions
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'environment', P_ENVIRONMENT,
            'warehouse_name', v_warehouse_name,
            'actions_attempted', v_actions
        );
END;
$$;

-- =============================================================================
-- GRANTS: Procedure Execution Permissions
-- =============================================================================
-- Grant USAGE on this procedure to the roles that need to execute it.
-- The procedure uses EXECUTE AS CALLER, so callers need appropriate privileges.
-- =============================================================================

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRF_TST_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRF_UAT_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRF_PPE_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRF_PRD_DBADMIN;

-- =============================================================================
-- VERIFICATION
-- =============================================================================
-- After deployment, verify the procedure exists:
--   SHOW PROCEDURES LIKE 'RBAC_CREATE_WAREHOUSE' IN SCHEMA ADMIN.RBAC;
--   DESCRIBE PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(VARCHAR, VARCHAR, INTEGER, VARCHAR);
-- =============================================================================
