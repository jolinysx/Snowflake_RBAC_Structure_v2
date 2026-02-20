-- ============================================================================
-- Redeploy Fixed RBAC_INITIAL_CONFIG Procedure
-- ============================================================================
-- Run this script to update the procedure with the fixes for:
-- 1. DEFAULT_SECONDARY_ROLES (not an account-level parameter)
-- 2. APPLY ROW ACCESS POLICY ON ACCOUNT (unsupported feature)
-- ============================================================================

USE DATABASE TEMP_RBAC;
USE SCHEMA CONFIG;