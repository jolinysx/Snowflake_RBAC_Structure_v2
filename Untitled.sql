-- ============================================================================
-- RBAC INITIAL CONFIGURATION - FIX AND REDEPLOY
-- ============================================================================

USE DATABASE TEMP_RBAC;
USE SCHEMA CONFIG;

-- Step 1: Redeploy the fixed procedure (copy the entire RBAC_SP_Initial_Config.sql content here or run it separately)

-- Step 2: Test in preview mode first
CALL RBAC_INITIAL_CONFIG(NULL, FALSE);

-- Step 3: Check for errors
SELECT 
    value:section::STRING as section,
    value:action::STRING as action,
    value:error::STRING as error_message
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())),
LATERAL FLATTEN(input => RBAC_INITIAL_CONFIG:errors);