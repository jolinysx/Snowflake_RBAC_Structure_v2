-- Test compilation of RBAC_INITIAL_CONFIG procedure
USE DATABASE TEMP_RBAC;
USE SCHEMA CONFIG;

-- Execute the stored procedure file
-- Copy the procedure from RBAC_SP_Initial_Config.sql and execute it here
-- For now, let's verify basic syntax with a minimal test

CREATE OR REPLACE SECURE PROCEDURE RBAC_INITIAL_CONFIG_TEST(
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
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    IF P_ENVIRONMENTS IS NULL THEN
        v_environments := ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PPE', 'PRD');
    ELSE
        v_environments := P_ENVIRONMENTS;
    END IF;
    
    -- Test ARRAY_CONTAINS syntax
    IF ARRAY_CONTAINS('DEV'::VARIANT, v_environments) THEN
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'test', 'passed',
            'message', 'ARRAY_CONTAINS works'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'actions', v_actions
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

-- Test call
CALL RBAC_INITIAL_CONFIG_TEST(NULL, TRUE);
