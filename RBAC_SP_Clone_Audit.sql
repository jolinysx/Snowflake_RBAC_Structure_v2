/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Audit & Compliance
 * 
 * Purpose: Track clone operations, enforce compliance policies, and provide
 *          audit reporting for clone management activities
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          CLONES
 *   Object Type:     TABLES (4), PROCEDURES (~8)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and CLONES schema must exist
 *     - RBAC_SP_Clone_Management.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * AUDIT CAPABILITIES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Full audit trail of all clone operations (create, delete, access)
 *   • Compliance policy definition and enforcement
 *   • Usage pattern analysis and reporting
 *   • Policy violation detection and alerting
 *   • Retention compliance tracking
 * 
 * COMPLIANCE POLICIES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Maximum clone age policies
 *   • Data classification restrictions
 *   • Environment-specific rules
 *   • User quota enforcement
 *   • Sensitive data clone restrictions
 * 
 * INTEGRATION:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Works alongside RBAC_SP_Clone_Management.sql to provide comprehensive
 *   clone governance and compliance monitoring.
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA CLONES;

-- #############################################################################
-- SECTION 1: AUDIT TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    OPERATION VARCHAR(50) NOT NULL,
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    CLONE_TYPE VARCHAR(20),
    ENVIRONMENT VARCHAR(10),
    SOURCE_DATABASE VARCHAR(255),
    SOURCE_SCHEMA VARCHAR(255),
    PERFORMED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    PERFORMED_BY_ROLE VARCHAR(255) DEFAULT CURRENT_ROLE(),
    SESSION_ID VARCHAR(100) DEFAULT CURRENT_SESSION(),
    CLIENT_IP VARCHAR(50),
    STATUS VARCHAR(20),
    ERROR_MESSAGE TEXT,
    METADATA VARIANT,
    POLICY_VIOLATIONS ARRAY
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_POLICIES (
    POLICY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_NAME VARCHAR(255) NOT NULL UNIQUE,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    ENVIRONMENT VARCHAR(10),
    DESCRIPTION TEXT,
    POLICY_DEFINITION VARIANT NOT NULL,
    SEVERITY VARCHAR(20) DEFAULT 'WARNING',
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(255),
    UPDATED_AT TIMESTAMP_NTZ
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_POLICY_VIOLATIONS (
    VIOLATION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    POLICY_ID VARCHAR(36) NOT NULL,
    POLICY_NAME VARCHAR(255),
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    VIOLATED_BY VARCHAR(255),
    VIOLATION_DETAILS VARIANT,
    SEVERITY VARCHAR(20),
    STATUS VARCHAR(20) DEFAULT 'OPEN',
    RESOLVED_BY VARCHAR(255),
    RESOLVED_AT TIMESTAMP_NTZ,
    RESOLUTION_NOTES TEXT,
    FOREIGN KEY (POLICY_ID) REFERENCES RBAC_CLONE_POLICIES(POLICY_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_ACCESS_LOG (
    ACCESS_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    ACCESSED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    ACCESS_TYPE VARCHAR(50),
    QUERY_ID VARCHAR(100),
    ROWS_ACCESSED INTEGER,
    SESSION_ID VARCHAR(100) DEFAULT CURRENT_SESSION()
);

-- Note: Indexes are not needed for regular Snowflake tables
-- Snowflake automatically optimizes query performance through micro-partitioning and pruning

-- #############################################################################
-- SECTION 2: AUDIT LOGGING PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Clone Operation
 * 
 * Purpose: Records clone operations to the audit log
 *          Called internally by clone management procedures
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_OPERATION(
    P_OPERATION VARCHAR,
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_CLONE_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR,
    P_STATUS VARCHAR,
    P_ERROR_MESSAGE TEXT DEFAULT NULL,
    P_METADATA VARIANT DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_audit_id VARCHAR;
    v_policy_violations ARRAY := ARRAY_CONSTRUCT();
    v_violation VARIANT;
BEGIN
    v_audit_id := UUID_STRING();
    
    -- Check for policy violations if this is a CREATE operation
    IF (P_OPERATION = 'CREATE' AND P_STATUS = 'SUCCESS') THEN
        CALL ADMIN.CLONES.RBAC_CHECK_CLONE_POLICIES(
            P_CLONE_ID, P_CLONE_NAME, P_CLONE_TYPE, 
            P_ENVIRONMENT, P_SOURCE_DATABASE, P_SOURCE_SCHEMA
        ) INTO v_violation;
        
        IF (v_violation:violations IS NOT NULL) THEN
            v_policy_violations := v_violation:violations;
        END IF;
    END IF;
    
    -- Insert audit record
    INSERT INTO RBAC_CLONE_AUDIT_LOG (
        AUDIT_ID, OPERATION, CLONE_ID, CLONE_NAME, CLONE_TYPE,
        ENVIRONMENT, SOURCE_DATABASE, SOURCE_SCHEMA, STATUS,
        ERROR_MESSAGE, METADATA, POLICY_VIOLATIONS
    ) VALUES (
        v_audit_id, P_OPERATION, P_CLONE_ID, P_CLONE_NAME, P_CLONE_TYPE,
        P_ENVIRONMENT, P_SOURCE_DATABASE, P_SOURCE_SCHEMA, P_STATUS,
        P_ERROR_MESSAGE, P_METADATA, v_policy_violations
    );
    
    RETURN v_audit_id;

EXCEPTION
    WHEN OTHER THEN
        -- Don't fail the main operation if audit fails
        RETURN NULL;
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Clone Access
 * 
 * Purpose: Records when users access clone data
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_ACCESS(
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_ACCESS_TYPE VARCHAR,
    P_QUERY_ID VARCHAR DEFAULT NULL,
    P_ROWS_ACCESSED INTEGER DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_id VARCHAR;
BEGIN
    v_access_id := UUID_STRING();
    
    INSERT INTO RBAC_CLONE_ACCESS_LOG (
        ACCESS_ID, CLONE_ID, CLONE_NAME, ACCESS_TYPE, QUERY_ID, ROWS_ACCESSED
    ) VALUES (
        v_access_id, P_CLONE_ID, P_CLONE_NAME, P_ACCESS_TYPE, P_QUERY_ID, P_ROWS_ACCESSED
    );
    
    RETURN v_access_id;

EXCEPTION
    WHEN OTHER THEN
        RETURN NULL;
END;
$$;

-- #############################################################################
-- SECTION 3: COMPLIANCE POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Clone Policy
 * 
 * Purpose: Creates a compliance policy for clone management
 * 
 * Policy Types:
 *   - MAX_AGE: Maximum age for clones
 *   - RESTRICTED_SOURCE: Sources that cannot be cloned
 *   - DATA_CLASSIFICATION: Restrict cloning based on data classification
 *   - USER_QUOTA: Additional quota restrictions
 *   - ENVIRONMENT_RESTRICTION: Environment-specific rules
 *   - TIME_RESTRICTION: Time-based restrictions
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE_POLICY(
    P_POLICY_NAME VARCHAR,
    P_POLICY_TYPE VARCHAR,
    P_POLICY_DEFINITION VARIANT,
    P_ENVIRONMENT VARCHAR,
    P_DESCRIPTION TEXT,
    P_SEVERITY VARCHAR
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var severity = P_SEVERITY || 'WARNING';
    
    // Validate policy type
    var validTypes = ['MAX_AGE', 'RESTRICTED_SOURCE', 'DATA_CLASSIFICATION', 
                      'USER_QUOTA', 'ENVIRONMENT_RESTRICTION', 'TIME_RESTRICTION',
                      'SENSITIVE_DATA', 'APPROVAL_REQUIRED'];
    if (!validTypes.includes(P_POLICY_TYPE)) {
        return {
            status: 'ERROR',
            message: 'Invalid policy type. Valid types: ' + validTypes.join(', ')
        };
    }
    
    // Validate severity
    var validSeverities = ['INFO', 'WARNING', 'ERROR', 'CRITICAL'];
    if (!validSeverities.includes(severity)) {
        return {
            status: 'ERROR',
            message: 'Invalid severity. Valid values: ' + validSeverities.join(', ')
        };
    }
    
    var policy_id = '';
    var stmt = snowflake.createStatement({
        sqlText: "SELECT UUID_STRING()"
    });
    var rs = stmt.execute();
    if (rs.next()) {
        policy_id = rs.getColumnValue(1);
    }
    
    // Insert policy
    var insertStmt = snowflake.createStatement({
        sqlText: `INSERT INTO RBAC_CLONE_POLICIES (
            POLICY_ID, POLICY_NAME, POLICY_TYPE, ENVIRONMENT,
            DESCRIPTION, POLICY_DEFINITION, SEVERITY
        ) VALUES (?, ?, ?, ?, ?, PARSE_JSON(?), ?)`,
        binds: [policy_id, P_POLICY_NAME, P_POLICY_TYPE, P_ENVIRONMENT,
                P_DESCRIPTION, JSON.stringify(P_POLICY_DEFINITION), severity]
    });
    insertStmt.execute();
    
    // Log the policy creation
    var logStmt = snowflake.createStatement({
        sqlText: `CALL RBAC_LOG_CLONE_OPERATION(?, ?, ?, ?, ?, NULL, NULL, ?, NULL, 
                  OBJECT_CONSTRUCT('policy_type', ?, 'severity', ?))`,
        binds: ['POLICY_CREATE', policy_id, P_POLICY_NAME, 'POLICY',
                P_ENVIRONMENT, 'SUCCESS', P_POLICY_TYPE, severity]
    });
    
    try {
        logStmt.execute();
    } catch(err) {
        // Log error but continue
    }
    
    return {
        status: 'SUCCESS',
        policy_id: policy_id,
        policy_name: P_POLICY_NAME,
        policy_type: P_POLICY_TYPE,
        message: 'Policy created successfully'
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Default Policies
 * 
 * Purpose: Creates a set of recommended default compliance policies
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE RBAC_SETUP_DEFAULT_CLONE_POLICIES()
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var policies_created = [];
    
    // Helper function to create policy
    function createPolicy(name, type, definition, environment, description, severity) {
        try {
            var stmt = snowflake.createStatement({
                sqlText: `CALL RBAC_CREATE_CLONE_POLICY(?, ?, ?, ?, ?, ?)`,
                binds: [name, type, definition, environment, description, severity]
            });
            var rs = stmt.execute();
            if (rs.next()) {
                var result = rs.getColumnValue(1);
                if (result.status === 'SUCCESS') {
                    policies_created.push(result.policy_name);
                }
            }
        } catch(err) {
            // Continue on error
        }
    }
    
    // Policy 1: Maximum clone age for PRD environment
    createPolicy(
        'PRD_MAX_CLONE_AGE_7_DAYS',
        'MAX_AGE',
        {max_age_days: 7, action: 'WARN_AND_LOG'},
        'PRD',
        'Production clones must not exceed 7 days to minimize data exposure risk',
        'WARNING'
    );
    
    // Policy 2: Maximum clone age for UAT
    createPolicy(
        'UAT_MAX_CLONE_AGE_14_DAYS',
        'MAX_AGE',
        {max_age_days: 14, action: 'WARN_AND_LOG'},
        'UAT',
        'UAT clones must not exceed 14 days',
        'WARNING'
    );
    
    // Policy 3: Restrict cloning of PII schemas
    createPolicy(
        'RESTRICT_PII_SCHEMA_CLONES',
        'SENSITIVE_DATA',
        {
            restricted_schemas: ['PII', 'SENSITIVE', 'CONFIDENTIAL', 'PHI', 'PCI'],
            action: 'REQUIRE_APPROVAL',
            approvers: ['SRS_SECURITY_ADMIN', 'SRS_ACCOUNT_ADMIN']
        },
        null,
        'Schemas containing PII data require approval before cloning',
        'CRITICAL'
    );
    
    // Policy 4: No PRD database clones
    createPolicy(
        'NO_PRD_DATABASE_CLONES',
        'ENVIRONMENT_RESTRICTION',
        {restricted_clone_types: ['DATABASE'], action: 'BLOCK'},
        'PRD',
        'Database-level clones are not permitted in production',
        'ERROR'
    );
    
    // Policy 5: Business hours only for PRD
    createPolicy(
        'PRD_BUSINESS_HOURS_ONLY',
        'TIME_RESTRICTION',
        {
            allowed_hours_start: 8,
            allowed_hours_end: 18,
            allowed_days: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
            timezone: 'America/New_York',
            action: 'BLOCK'
        },
        'PRD',
        'Production clones can only be created during business hours (8 AM - 6 PM)',
        'ERROR'
    );
    
    // Policy 6: Maximum total clones per user across all environments
    createPolicy(
        'MAX_TOTAL_USER_CLONES_10',
        'USER_QUOTA',
        {max_total_clones: 10, action: 'BLOCK'},
        null,
        'Users cannot have more than 10 total active clones across all environments',
        'ERROR'
    );
    
    // Policy 7: Audit trail retention
    createPolicy(
        'AUDIT_RETENTION_365_DAYS',
        'DATA_CLASSIFICATION',
        {retention_days: 365, applies_to: 'AUDIT_LOG'},
        null,
        'Clone audit records must be retained for 365 days for compliance',
        'INFO'
    );
    
    return {
        status: 'SUCCESS',
        policies_created: policies_created,
        count: policies_created.length,
        message: 'Default policies have been created'
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Clone Policies
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_LIST_CLONE_POLICIES(
    P_ENVIRONMENT VARCHAR,
    P_POLICY_TYPE VARCHAR,
    P_ACTIVE_ONLY BOOLEAN
)
RETURNS TABLE (
    POLICY_ID VARCHAR,
    POLICY_NAME VARCHAR,
    POLICY_TYPE VARCHAR,
    ENVIRONMENT VARCHAR,
    SEVERITY VARCHAR,
    IS_ACTIVE BOOLEAN,
    DESCRIPTION TEXT,
    CREATED_AT TIMESTAMP_NTZ
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            POLICY_ID,
            POLICY_NAME,
            POLICY_TYPE,
            ENVIRONMENT,
            SEVERITY,
            IS_ACTIVE,
            DESCRIPTION,
            CREATED_AT
        FROM RBAC_CLONE_POLICIES
        WHERE (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT OR ENVIRONMENT IS NULL)
          AND (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
          AND (NOT P_ACTIVE_ONLY OR IS_ACTIVE = TRUE)
        ORDER BY SEVERITY DESC, POLICY_NAME
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Enable/Disable Policy
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE RBAC_SET_POLICY_STATUS(
    P_POLICY_NAME VARCHAR,
    P_IS_ACTIVE BOOLEAN
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Update the policy status
    var updateStmt = snowflake.createStatement({
        sqlText: `UPDATE RBAC_CLONE_POLICIES
                  SET IS_ACTIVE = ?,
                      UPDATED_BY = CURRENT_USER(),
                      UPDATED_AT = CURRENT_TIMESTAMP()
                  WHERE POLICY_NAME = ?`,
        binds: [P_IS_ACTIVE, P_POLICY_NAME]
    });
    updateStmt.execute();
    
    // Check if policy exists
    var checkStmt = snowflake.createStatement({
        sqlText: `SELECT COUNT(*) AS CNT FROM RBAC_CLONE_POLICIES WHERE POLICY_NAME = ?`,
        binds: [P_POLICY_NAME]
    });
    var rs = checkStmt.execute();
    rs.next();
    
    if (rs.getColumnValue(1) === 0) {
        return {
            status: 'ERROR',
            message: 'Policy not found'
        };
    }
    
    return {
        status: 'SUCCESS',
        policy_name: P_POLICY_NAME,
        is_active: P_IS_ACTIVE,
        message: 'Policy status updated'
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Delete Policy
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_DELETE_CLONE_POLICY(
    P_POLICY_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Get policy ID
    var stmt = snowflake.createStatement({
        sqlText: `SELECT POLICY_ID FROM RBAC_CLONE_POLICIES WHERE POLICY_NAME = ?`,
        binds: [P_POLICY_NAME]
    });
    var rs = stmt.execute();
    
    if (!rs.next()) {
        return {
            status: 'ERROR',
            message: 'Policy not found'
        };
    }
    
    var policy_id = rs.getColumnValue(1);
    
    // Delete policy
    var deleteStmt = snowflake.createStatement({
        sqlText: `DELETE FROM RBAC_CLONE_POLICIES WHERE POLICY_NAME = ?`,
        binds: [P_POLICY_NAME]
    });
    deleteStmt.execute();
    
    // Log deletion
    try {
        var logStmt = snowflake.createStatement({
            sqlText: `CALL RBAC_LOG_CLONE_OPERATION(?, ?, ?, ?, NULL, NULL, NULL, ?, NULL, NULL)`,
            binds: ['POLICY_DELETE', policy_id, P_POLICY_NAME, 'POLICY', 'SUCCESS']
        });
        logStmt.execute();
    } catch(err) {
        // Continue even if logging fails
    }
    
    return {
        status: 'SUCCESS',
        policy_name: P_POLICY_NAME,
        message: 'Policy deleted'
    };
$$;

-- #############################################################################
-- SECTION 4: POLICY ENFORCEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Clone Policies
 * 
 * Purpose: Evaluates all active policies against a clone operation
 *          Returns any violations found
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_POLICIES(
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_CLONE_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var violations = [];
    var shouldBlock = false;
    
    // Get current user
    var userStmt = snowflake.createStatement({
        sqlText: "SELECT CURRENT_USER()"
    });
    var userRs = userStmt.execute();
    userRs.next();
    var currentUser = userRs.getColumnValue(1);
    
    // Get current time info
    var timeStmt = snowflake.createStatement({
        sqlText: "SELECT HOUR(CURRENT_TIMESTAMP()) AS HR, DAYNAME(CURRENT_DATE()) AS DAY"
    });
    var timeRs = timeStmt.execute();
    timeRs.next();
    var currentHour = timeRs.getColumnValue('HR');
    var currentDay = timeRs.getColumnValue('DAY');
    
    // Get total user clones
    var cloneCountStmt = snowflake.createStatement({
        sqlText: "SELECT COUNT(*) AS CNT FROM RBAC_CLONE_REGISTRY WHERE CREATED_BY = ? AND STATUS = 'ACTIVE'",
        binds: [currentUser]
    });
    var cloneCountRs = cloneCountStmt.execute();
    cloneCountRs.next();
    var totalUserClones = cloneCountRs.getColumnValue('CNT');
    
    // Get all active policies
    var policiesStmt = snowflake.createStatement({
        sqlText: `SELECT POLICY_ID, POLICY_NAME, POLICY_TYPE, ENVIRONMENT, POLICY_DEFINITION, SEVERITY
                  FROM RBAC_CLONE_POLICIES
                  WHERE IS_ACTIVE = TRUE
                    AND (ENVIRONMENT IS NULL OR ENVIRONMENT = ?)`,
        binds: [P_ENVIRONMENT]
    });
    var policiesRs = policiesStmt.execute();
    
    while (policiesRs.next()) {
        var policyId = policiesRs.getColumnValue('POLICY_ID');
        var policyName = policiesRs.getColumnValue('POLICY_NAME');
        var policyType = policiesRs.getColumnValue('POLICY_TYPE');
        var severity = policiesRs.getColumnValue('SEVERITY');
        var definition = policiesRs.getColumnValue('POLICY_DEFINITION');
        
        var violation = null;
        
        // Check policy based on type
        if (policyType === 'ENVIRONMENT_RESTRICTION') {
            if (definition.restricted_clone_types && definition.restricted_clone_types.includes(P_CLONE_TYPE)) {
                violation = {
                    policy_name: policyName,
                    policy_type: policyType,
                    severity: severity,
                    message: P_CLONE_TYPE + ' clones are not allowed in ' + P_ENVIRONMENT,
                    action: definition.action
                };
                if (definition.action === 'BLOCK') {
                    shouldBlock = true;
                }
            }
        } else if (policyType === 'USER_QUOTA') {
            if (totalUserClones >= definition.max_total_clones) {
                violation = {
                    policy_name: policyName,
                    policy_type: policyType,
                    severity: severity,
                    message: 'Total clone limit exceeded. You have ' + totalUserClones + ' clones (max: ' + definition.max_total_clones + ')',
                    action: definition.action
                };
                if (definition.action === 'BLOCK') {
                    shouldBlock = true;
                }
            }
        } else if (policyType === 'TIME_RESTRICTION') {
            var outsideHours = currentHour < definition.allowed_hours_start || currentHour >= definition.allowed_hours_end;
            var wrongDay = !definition.allowed_days || !definition.allowed_days.includes(currentDay.substring(0, 3).toUpperCase());
            
            if (outsideHours || wrongDay) {
                violation = {
                    policy_name: policyName,
                    policy_type: policyType,
                    severity: severity,
                    message: 'Clone creation not allowed at this time. Allowed: ' + definition.allowed_hours_start + ':00 - ' + definition.allowed_hours_end + ':00',
                    action: definition.action
                };
                if (definition.action === 'BLOCK') {
                    shouldBlock = true;
                }
            }
        } else if (policyType === 'SENSITIVE_DATA') {
            if (P_SOURCE_SCHEMA && definition.restricted_schemas) {
                for (var i = 0; i < definition.restricted_schemas.length; i++) {
                    if (P_SOURCE_SCHEMA.toUpperCase().includes(definition.restricted_schemas[i])) {
                        violation = {
                            policy_name: policyName,
                            policy_type: policyType,
                            severity: severity,
                            message: 'Schema contains sensitive data and requires approval',
                            action: definition.action,
                            approvers: definition.approvers
                        };
                        if (definition.action === 'BLOCK' || definition.action === 'REQUIRE_APPROVAL') {
                            shouldBlock = true;
                        }
                        break;
                    }
                }
            }
        }
        
        // Record violation if found
        if (violation) {
            violations.push(violation);
            
            // Log the violation
            try {
                var insertStmt = snowflake.createStatement({
                    sqlText: `INSERT INTO RBAC_CLONE_POLICY_VIOLATIONS (
                        POLICY_ID, POLICY_NAME, CLONE_ID, CLONE_NAME,
                        VIOLATED_BY, VIOLATION_DETAILS, SEVERITY
                    ) VALUES (?, ?, ?, ?, ?, PARSE_JSON(?), ?)`,
                    binds: [policyId, policyName, P_CLONE_ID, P_CLONE_NAME,
                            currentUser, JSON.stringify(violation), severity]
                });
                insertStmt.execute();
            } catch(err) {
                // Continue even if logging fails
            }
        }
    }
    
    return {
        has_violations: violations.length > 0,
        should_block: shouldBlock,
        violations_count: violations.length,
        violations: violations
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Clone Compliance
 * 
 * Purpose: Checks all existing clones for policy compliance
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_COMPLIANCE(
    P_ENVIRONMENT VARCHAR
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var violations = [];
    var compliantCount = 0;
    var nonCompliantCount = 0;
    
    // Get all active clones
    var clonesStmt = snowflake.createStatement({
        sqlText: `SELECT 
            CLONE_ID, CLONE_NAME, CLONE_TYPE, ENVIRONMENT,
            SOURCE_DATABASE, SOURCE_SCHEMA, CREATED_BY, CREATED_AT,
            DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP()) AS AGE_DAYS
        FROM RBAC_CLONE_REGISTRY
        WHERE STATUS = 'ACTIVE'
          AND (? IS NULL OR ENVIRONMENT = ?)`,
        binds: [P_ENVIRONMENT, P_ENVIRONMENT]
    });
    var clonesRs = clonesStmt.execute();
    
    while (clonesRs.next()) {
        var cloneId = clonesRs.getColumnValue('CLONE_ID');
        var cloneName = clonesRs.getColumnValue('CLONE_NAME');
        var environment = clonesRs.getColumnValue('ENVIRONMENT');
        var createdBy = clonesRs.getColumnValue('CREATED_BY');
        var ageDays = clonesRs.getColumnValue('AGE_DAYS');
        
        var hasViolation = false;
        
        // Check MAX_AGE policies
        var policiesStmt = snowflake.createStatement({
            sqlText: `SELECT POLICY_NAME, POLICY_DEFINITION, SEVERITY
            FROM RBAC_CLONE_POLICIES
            WHERE IS_ACTIVE = TRUE
              AND POLICY_TYPE = 'MAX_AGE'
              AND (ENVIRONMENT IS NULL OR ENVIRONMENT = ?)`,
            binds: [environment]
        });
        var policiesRs = policiesStmt.execute();
        
        while (policiesRs.next()) {
            var policyName = policiesRs.getColumnValue('POLICY_NAME');
            var definition = policiesRs.getColumnValue('POLICY_DEFINITION');
            var severity = policiesRs.getColumnValue('SEVERITY');
            var maxAge = definition.max_age_days;
            
            if (ageDays > maxAge) {
                violations.push({
                    clone_name: cloneName,
                    clone_owner: createdBy,
                    policy_name: policyName,
                    violation: 'Clone age (' + ageDays + ' days) exceeds maximum (' + maxAge + ' days)',
                    severity: severity,
                    environment: environment
                });
                hasViolation = true;
            }
        }
        
        if (hasViolation) {
            nonCompliantCount++;
        } else {
            compliantCount++;
        }
    }
    
    var tsStmt = snowflake.createStatement({
        sqlText: "SELECT CURRENT_TIMESTAMP()"
    });
    var tsRs = tsStmt.execute();
    tsRs.next();
    var timestamp = tsRs.getColumnValue(1);
    
    return {
        status: 'SUCCESS',
        compliant_clones: compliantCount,
        non_compliant_clones: nonCompliantCount,
        violations: violations,
        scan_timestamp: timestamp
    };
$$;

-- #############################################################################
-- SECTION 5: AUDIT REPORTING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Clone Audit Log
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_AUDIT_LOG(
    P_START_DATE DATE,
    P_END_DATE DATE,
    P_OPERATION VARCHAR,
    P_USER VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_LIMIT INTEGER
)
RETURNS TABLE (
    AUDIT_ID VARCHAR,
    TIMESTAMP TIMESTAMP_NTZ,
    OPERATION VARCHAR,
    CLONE_NAME VARCHAR,
    ENVIRONMENT VARCHAR,
    PERFORMED_BY VARCHAR,
    STATUS VARCHAR,
    POLICY_VIOLATIONS INTEGER
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
    v_start TIMESTAMP_NTZ;
    v_end TIMESTAMP_NTZ;
    v_limit INTEGER;
BEGIN
    v_start := COALESCE(P_START_DATE::TIMESTAMP_NTZ, DATEADD(DAY, -30, CURRENT_TIMESTAMP()));
    v_end := COALESCE(P_END_DATE::TIMESTAMP_NTZ, CURRENT_TIMESTAMP());
    v_limit := COALESCE(P_LIMIT, 1000);
    
    res := (
        SELECT 
            AUDIT_ID,
            TIMESTAMP,
            OPERATION,
            CLONE_NAME,
            ENVIRONMENT,
            PERFORMED_BY,
            STATUS,
            ARRAY_SIZE(COALESCE(POLICY_VIOLATIONS, ARRAY_CONSTRUCT())) AS POLICY_VIOLATIONS
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP BETWEEN v_start AND v_end
          AND (P_OPERATION IS NULL OR OPERATION = P_OPERATION)
          AND (P_USER IS NULL OR PERFORMED_BY = P_USER)
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
        ORDER BY TIMESTAMP DESC
        LIMIT 1000
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Policy Violations Report
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_GET_POLICY_VIOLATIONS(
    P_STATUS VARCHAR,
    P_SEVERITY VARCHAR,
    P_START_DATE DATE,
    P_END_DATE DATE
)
RETURNS TABLE (
    VIOLATION_ID VARCHAR,
    TIMESTAMP TIMESTAMP_NTZ,
    POLICY_NAME VARCHAR,
    CLONE_NAME VARCHAR,
    VIOLATED_BY VARCHAR,
    SEVERITY VARCHAR,
    STATUS VARCHAR,
    RESOLUTION_NOTES TEXT
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
    v_start TIMESTAMP_NTZ;
    v_end TIMESTAMP_NTZ;
BEGIN
    v_start := COALESCE(P_START_DATE::TIMESTAMP_NTZ, DATEADD(DAY, -90, CURRENT_TIMESTAMP()));
    v_end := COALESCE(P_END_DATE::TIMESTAMP_NTZ, CURRENT_TIMESTAMP());
    
    res := (
        SELECT 
            VIOLATION_ID,
            TIMESTAMP,
            POLICY_NAME,
            CLONE_NAME,
            VIOLATED_BY,
            SEVERITY,
            STATUS,
            RESOLUTION_NOTES
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE TIMESTAMP BETWEEN v_start AND v_end
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
          AND (P_SEVERITY IS NULL OR SEVERITY = P_SEVERITY)
        ORDER BY 
            CASE SEVERITY WHEN 'CRITICAL' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'WARNING' THEN 3 ELSE 4 END,
            TIMESTAMP DESC
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Resolve Policy Violation
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_RESOLVE_POLICY_VIOLATION(
    P_VIOLATION_ID VARCHAR,
    P_RESOLUTION_NOTES TEXT
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Update violation status
    var updateStmt = snowflake.createStatement({
        sqlText: `UPDATE RBAC_CLONE_POLICY_VIOLATIONS
                  SET STATUS = 'RESOLVED',
                      RESOLVED_BY = CURRENT_USER(),
                      RESOLVED_AT = CURRENT_TIMESTAMP(),
                      RESOLUTION_NOTES = ?
                  WHERE VIOLATION_ID = ?`,
        binds: [P_RESOLUTION_NOTES, P_VIOLATION_ID]
    });
    updateStmt.execute();
    
    // Check if violation exists
    var checkStmt = snowflake.createStatement({
        sqlText: `SELECT COUNT(*) AS CNT FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE VIOLATION_ID = ?`,
        binds: [P_VIOLATION_ID]
    });
    var rs = checkStmt.execute();
    rs.next();
    
    if (rs.getColumnValue(1) === 0) {
        return {
            status: 'ERROR',
            message: 'Violation not found'
        };
    }
    
    // Get current user
    var userStmt = snowflake.createStatement({
        sqlText: `SELECT CURRENT_USER()`
    });
    var userRs = userStmt.execute();
    userRs.next();
    var currentUser = userRs.getColumnValue(1);
    
    return {
        status: 'SUCCESS',
        violation_id: P_VIOLATION_ID,
        resolved_by: currentUser,
        message: 'Violation marked as resolved'
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate Clone Audit Report
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE RBAC_GENERATE_CLONE_AUDIT_REPORT(
    P_START_DATE DATE,
    P_END_DATE DATE
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var start = P_START_DATE;
    var end = P_END_DATE;
    
    // Set defaults if not provided
    if (!start) {
        var stmt = snowflake.createStatement({
            sqlText: "SELECT DATEADD(DAY, -30, CURRENT_DATE())"
        });
        var rs = stmt.execute();
        rs.next();
        start = rs.getColumnValue(1);
    }
    
    if (!end) {
        var stmt = snowflake.createStatement({
            sqlText: "SELECT CURRENT_DATE()"
        });
        var rs = stmt.execute();
        rs.next();
        end = rs.getColumnValue(1);
    }
    
    // Summary statistics
    var summaryStmt = snowflake.createStatement({
        sqlText: `SELECT 
            COUNT(*) AS total_operations,
            COUNT_IF(STATUS = 'SUCCESS') AS successful,
            COUNT_IF(STATUS != 'SUCCESS') AS failed,
            COUNT_IF(OPERATION = 'CREATE') AS creates,
            COUNT_IF(OPERATION = 'DELETE') AS deletes,
            COUNT(DISTINCT PERFORMED_BY) AS unique_users
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN ? AND ?`,
        binds: [start, end]
    });
    var summaryRs = summaryStmt.execute();
    summaryRs.next();
    var summary = {
        total_operations: summaryRs.getColumnValue('TOTAL_OPERATIONS'),
        successful: summaryRs.getColumnValue('SUCCESSFUL'),
        failed: summaryRs.getColumnValue('FAILED'),
        creates: summaryRs.getColumnValue('CREATES'),
        deletes: summaryRs.getColumnValue('DELETES'),
        unique_users: summaryRs.getColumnValue('UNIQUE_USERS')
    };
    
    // By operation
    var byOpStmt = snowflake.createStatement({
        sqlText: `SELECT OPERATION, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN ? AND ?
        GROUP BY OPERATION`,
        binds: [start, end]
    });
    var byOperation = {};
    var byOpRs = byOpStmt.execute();
    while (byOpRs.next()) {
        byOperation[byOpRs.getColumnValue('OPERATION')] = byOpRs.getColumnValue('CNT');
    }
    
    // By user (top 10)
    var byUserStmt = snowflake.createStatement({
        sqlText: `SELECT PERFORMED_BY, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN ? AND ?
        GROUP BY PERFORMED_BY
        ORDER BY CNT DESC
        LIMIT 10`,
        binds: [start, end]
    });
    var topUsers = [];
    var byUserRs = byUserStmt.execute();
    while (byUserRs.next()) {
        topUsers.push({
            user: byUserRs.getColumnValue('PERFORMED_BY'),
            operations: byUserRs.getColumnValue('CNT')
        });
    }
    
    // By environment
    var byEnvStmt = snowflake.createStatement({
        sqlText: `SELECT COALESCE(ENVIRONMENT, 'N/A') AS ENV, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN ? AND ?
        GROUP BY ENVIRONMENT`,
        binds: [start, end]
    });
    var byEnvironment = {};
    var byEnvRs = byEnvStmt.execute();
    while (byEnvRs.next()) {
        byEnvironment[byEnvRs.getColumnValue('ENV')] = byEnvRs.getColumnValue('CNT');
    }
    
    // Policy violations summary
    var violationsStmt = snowflake.createStatement({
        sqlText: `SELECT 
            COUNT(*) AS total_violations,
            COUNT_IF(STATUS = 'OPEN') AS open,
            COUNT_IF(STATUS = 'RESOLVED') AS resolved,
            COUNT_IF(SEVERITY = 'CRITICAL') AS critical,
            COUNT_IF(SEVERITY = 'ERROR') AS error,
            COUNT_IF(SEVERITY = 'WARNING') AS warning
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE TIMESTAMP::DATE BETWEEN ? AND ?`,
        binds: [start, end]
    });
    var violationsRs = violationsStmt.execute();
    violationsRs.next();
    var policyViolations = {
        total_violations: violationsRs.getColumnValue('TOTAL_VIOLATIONS'),
        open: violationsRs.getColumnValue('OPEN'),
        resolved: violationsRs.getColumnValue('RESOLVED'),
        critical: violationsRs.getColumnValue('CRITICAL'),
        error: violationsRs.getColumnValue('ERROR'),
        warning: violationsRs.getColumnValue('WARNING')
    };
    
    // Get current timestamp and user
    var tsStmt = snowflake.createStatement({
        sqlText: "SELECT CURRENT_TIMESTAMP(), CURRENT_USER()"
    });
    var tsRs = tsStmt.execute();
    tsRs.next();
    var currentTimestamp = tsRs.getColumnValue(1);
    var currentUser = tsRs.getColumnValue(2);
    
    return {
        report_period: { start: start, end: end },
        summary: summary,
        by_operation: byOperation,
        top_users: topUsers,
        by_environment: byEnvironment,
        policy_violations: policyViolations,
        generated_at: currentTimestamp,
        generated_by: currentUser
    };
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get User Clone Activity
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(
    P_USERNAME VARCHAR,
    P_DAYS_BACK FLOAT
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var user = P_USERNAME;
    var daysBack = P_DAYS_BACK || 30;
    
    // Set default user if not provided
    if (!user) {
        var userStmt = snowflake.createStatement({
            sqlText: "SELECT CURRENT_USER()"
        });
        var userRs = userStmt.execute();
        userRs.next();
        user = userRs.getColumnValue(1);
    }
    
    // Current active clones
    var clonesStmt = snowflake.createStatement({
        sqlText: `SELECT 
            CLONE_NAME,
            ENVIRONMENT,
            CREATED_AT,
            DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP()) AS age_days
        FROM RBAC_CLONE_REGISTRY
        WHERE CREATED_BY = ? AND STATUS = 'ACTIVE'`,
        binds: [user]
    });
    var currentClones = [];
    var clonesRs = clonesStmt.execute();
    while (clonesRs.next()) {
        currentClones.push({
            clone_name: clonesRs.getColumnValue('CLONE_NAME'),
            environment: clonesRs.getColumnValue('ENVIRONMENT'),
            created_at: clonesRs.getColumnValue('CREATED_AT'),
            age_days: clonesRs.getColumnValue('AGE_DAYS')
        });
    }
    
    // Recent operations
    var opsStmt = snowflake.createStatement({
        sqlText: `SELECT 
            OPERATION,
            CLONE_NAME,
            TIMESTAMP,
            STATUS
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE PERFORMED_BY = ?
          AND TIMESTAMP >= DATEADD(DAY, ?, CURRENT_TIMESTAMP())
        ORDER BY TIMESTAMP DESC
        LIMIT 50`,
        binds: [user, -daysBack]
    });
    var recentOperations = [];
    var opsRs = opsStmt.execute();
    while (opsRs.next()) {
        recentOperations.push({
            operation: opsRs.getColumnValue('OPERATION'),
            clone_name: opsRs.getColumnValue('CLONE_NAME'),
            timestamp: opsRs.getColumnValue('TIMESTAMP'),
            status: opsRs.getColumnValue('STATUS')
        });
    }
    
    // Policy violations
    var violationsStmt = snowflake.createStatement({
        sqlText: `SELECT 
            POLICY_NAME,
            TIMESTAMP,
            SEVERITY,
            STATUS
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE VIOLATED_BY = ?
          AND TIMESTAMP >= DATEADD(DAY, ?, CURRENT_TIMESTAMP())`,
        binds: [user, -daysBack]
    });
    var violations = [];
    var violationsRs = violationsStmt.execute();
    while (violationsRs.next()) {
        violations.push({
            policy_name: violationsRs.getColumnValue('POLICY_NAME'),
            timestamp: violationsRs.getColumnValue('TIMESTAMP'),
            severity: violationsRs.getColumnValue('SEVERITY'),
            status: violationsRs.getColumnValue('STATUS')
        });
    }
    
    return {
        user: user,
        active_clones: currentClones,
        active_clone_count: currentClones.length,
        recent_operations: recentOperations,
        policy_violations: violations,
        days_analyzed: daysBack
    };
$$;

-- #############################################################################
-- SECTION 6: MAINTENANCE & CLEANUP
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Purge Old Audit Records
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.CLONES.RBAC_PURGE_CLONE_AUDIT_RECORDS(
    P_RETENTION_DAYS FLOAT,
    P_DRY_RUN BOOLEAN
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    var retentionDays = P_RETENTION_DAYS || 365;
    var dryRun = (P_DRY_RUN === null || P_DRY_RUN === undefined) ? true : P_DRY_RUN;
    
    // Calculate cutoff date
    var cutoffStmt = snowflake.createStatement({
        sqlText: "SELECT DATEADD(DAY, ?, CURRENT_TIMESTAMP())",
        binds: [-retentionDays]
    });
    var cutoffRs = cutoffStmt.execute();
    cutoffRs.next();
    var cutoffDate = cutoffRs.getColumnValue(1);
    
    // Count records to be purged - audit log
    var auditCountStmt = snowflake.createStatement({
        sqlText: "SELECT COUNT(*) AS CNT FROM RBAC_CLONE_AUDIT_LOG WHERE TIMESTAMP < ?",
        binds: [cutoffDate]
    });
    var auditCountRs = auditCountStmt.execute();
    auditCountRs.next();
    var auditCount = auditCountRs.getColumnValue('CNT');
    
    // Count records to be purged - violations
    var violationCountStmt = snowflake.createStatement({
        sqlText: "SELECT COUNT(*) AS CNT FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE TIMESTAMP < ? AND STATUS = 'RESOLVED'",
        binds: [cutoffDate]
    });
    var violationCountRs = violationCountStmt.execute();
    violationCountRs.next();
    var violationCount = violationCountRs.getColumnValue('CNT');
    
    // Count records to be purged - access log
    var accessCountStmt = snowflake.createStatement({
        sqlText: "SELECT COUNT(*) AS CNT FROM RBAC_CLONE_ACCESS_LOG WHERE TIMESTAMP < ?",
        binds: [cutoffDate]
    });
    var accessCountRs = accessCountStmt.execute();
    accessCountRs.next();
    var accessCount = accessCountRs.getColumnValue('CNT');
    
    // Perform actual deletion if not dry run
    if (!dryRun) {
        snowflake.createStatement({
            sqlText: "DELETE FROM RBAC_CLONE_AUDIT_LOG WHERE TIMESTAMP < ?",
            binds: [cutoffDate]
        }).execute();
        
        snowflake.createStatement({
            sqlText: "DELETE FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE TIMESTAMP < ? AND STATUS = 'RESOLVED'",
            binds: [cutoffDate]
        }).execute();
        
        snowflake.createStatement({
            sqlText: "DELETE FROM RBAC_CLONE_ACCESS_LOG WHERE TIMESTAMP < ?",
            binds: [cutoffDate]
        }).execute();
    }
    
    var message = dryRun 
        ? 'Dry run complete. Set P_DRY_RUN=FALSE to purge records.'
        : 'Audit records older than ' + retentionDays + ' days have been purged.';
    
    return {
        status: 'SUCCESS',
        mode: dryRun ? 'DRY_RUN' : 'EXECUTED',
        retention_days: retentionDays,
        cutoff_date: cutoffDate,
        records_affected: {
            audit_log: auditCount,
            violations: violationCount,
            access_log: accessCount,
            total: auditCount + violationCount + accessCount
        },
        message: message
    };
$$;

-- #############################################################################
-- SECTION 7: GRANT PERMISSIONS
-- #############################################################################

-- Audit logging (internal use)
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_OPERATION(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARIANT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SYSTEM_ADMIN;

-- Policy management (admin only)
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE_POLICY(VARCHAR, VARCHAR, VARIANT, VARCHAR, TEXT, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_DEFAULT_CLONE_POLICIES() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LIST_CLONE_POLICIES(VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_SET_POLICY_STATUS(VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_DELETE_CLONE_POLICY(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- Policy enforcement
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_POLICIES(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_COMPLIANCE(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- Audit reporting
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_AUDIT_LOG(DATE, DATE, VARCHAR, VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_GET_POLICY_VIOLATIONS(VARCHAR, VARCHAR, DATE, DATE) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_RESOLVE_POLICY_VIOLATION(VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GENERATE_CLONE_AUDIT_REPORT(DATE, DATE) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(VARCHAR, FLOAT) TO ROLE SRS_SECURITY_ADMIN;

-- Allow users to see their own activity
GRANT USAGE ON PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(VARCHAR, FLOAT) TO ROLE PUBLIC;

-- Maintenance
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_PURGE_CLONE_AUDIT_RECORDS(FLOAT, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
