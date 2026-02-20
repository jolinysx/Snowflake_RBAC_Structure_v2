-- Test compilation of RBAC_INITIAL_CONFIG
-- This file should be run after fixing RBAC_SP_Initial_Config.sql

USE DATABASE TEMP_RBAC;
USE SCHEMA CONFIG;

-- The procedure should now compile successfully
-- Run the entire RBAC_SP_Initial_Config.sql file first

-- Then test with:
-- CALL RBAC_INITIAL_CONFIG(NULL, FALSE);
