/*******************************************************************************
 * RBAC STORED PROCEDURE: DevOps Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of CI/CD pipelines, deployments, and releases
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          DEVOPS
 *   Object Type:     TABLES (3), PROCEDURES (~5)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_DEVOPS, SRS_SECURITY_ADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and DEVOPS schema must exist
 *     - RBAC_SP_DevOps.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DASHBOARD COMPONENTS:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Pipeline Status           - Active pipelines and their health
 *   • Deployment Tracking       - Recent deployments by environment
 *   • Release Management        - Version tracking and rollback history
 *   • Git Integration Status    - Repository sync and branch activity
 *   • Change Analytics          - Deployment frequency and patterns
 *   • Failure Analysis          - Failed deployments and root causes
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA DEVOPS;

-- #############################################################################
-- SECTION 1: DEVOPS TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_PIPELINE_STATUS (
    STATUS_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    PIPELINE_NAME VARCHAR(255) NOT NULL,
    PIPELINE_TYPE VARCHAR(50),
    PLATFORM VARCHAR(50),
    DOMAIN VARCHAR(100),
    LAST_RUN_ID VARCHAR(255),
    LAST_RUN_STATUS VARCHAR(20),
    LAST_RUN_AT TIMESTAMP_NTZ,
    CONSECUTIVE_FAILURES INTEGER DEFAULT 0,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    HEALTH_STATUS VARCHAR(20) DEFAULT 'UNKNOWN',
    METADATA VARIANT,
    UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_RELEASES (
    RELEASE_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    VERSION VARCHAR(50) NOT NULL,
    RELEASE_NAME VARCHAR(255),
    ENVIRONMENT VARCHAR(10) NOT NULL,
    DATABASE_NAME VARCHAR(255),
    SCHEMA_NAME VARCHAR(255),
    RELEASE_TYPE VARCHAR(50),
    RELEASE_NOTES TEXT,
    COMMIT_SHA VARCHAR(100),
    BRANCH_NAME VARCHAR(255),
    TAG_NAME VARCHAR(100),
    DEPLOYED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    DEPLOYED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PREVIOUS_VERSION VARCHAR(50),
    STATUS VARCHAR(20) DEFAULT 'DEPLOYED',
    ROLLBACK_OF VARCHAR(36),
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_CHANGE_LOG (
    CHANGE_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    CHANGE_TYPE VARCHAR(50) NOT NULL,
    ENVIRONMENT VARCHAR(10),
    DATABASE_NAME VARCHAR(255),
    SCHEMA_NAME VARCHAR(255),
    OBJECT_TYPE VARCHAR(50),
    OBJECT_NAME VARCHAR(255),
    CHANGE_DESCRIPTION TEXT,
    PREVIOUS_STATE VARIANT,
    NEW_STATE VARIANT,
    CHANGED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CHANGED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    DEPLOYMENT_ID VARCHAR(36),
    RELEASE_ID VARCHAR(36),
    COMMIT_SHA VARCHAR(100),
    IS_BREAKING_CHANGE BOOLEAN DEFAULT FALSE
);

-- #############################################################################
-- SECTION 2: PIPELINE STATUS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Pipeline Status Dashboard
 * 
 * Purpose: Real-time status of all CI/CD pipelines
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_PIPELINE_STATUS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_pipeline_status ARRAY;
    v_by_platform VARIANT;
    v_by_health VARIANT;
    v_failing_pipelines ARRAY;
    v_recent_runs ARRAY;
    v_total_pipelines INTEGER;
    v_healthy_count INTEGER;
BEGIN
    -- Get pipeline statuses from deployment history
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'pipeline_name', PIPELINE_NAME,
        'last_run_status', LAST_STATUS,
        'last_run_at', LAST_RUN,
        'success_rate', SUCCESS_RATE,
        'total_runs', TOTAL_RUNS,
        'health', CASE 
            WHEN SUCCESS_RATE >= 90 THEN 'HEALTHY'
            WHEN SUCCESS_RATE >= 70 THEN 'WARNING'
            ELSE 'FAILING'
        END
    )) INTO v_pipeline_status
    FROM (
        SELECT 
            PIPELINE_NAME,
            MAX(CASE WHEN STATUS = 'SUCCESS' THEN 'SUCCESS' ELSE STATUS END) AS LAST_STATUS,
            MAX(STARTED_AT) AS LAST_RUN,
            ROUND(COUNT_IF(STATUS = 'SUCCESS') * 100.0 / NULLIF(COUNT(*), 0), 1) AS SUCCESS_RATE,
            COUNT(*) AS TOTAL_RUNS
        FROM DEVOPS_DEPLOYMENTS
        WHERE PIPELINE_NAME IS NOT NULL
          AND STARTED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
        GROUP BY PIPELINE_NAME
        ORDER BY LAST_RUN DESC
    );
    
    v_total_pipelines := ARRAY_SIZE(COALESCE(v_pipeline_status, ARRAY_CONSTRUCT()));
    
    -- Count healthy pipelines
    SELECT COUNT(*) INTO v_healthy_count
    FROM TABLE(FLATTEN(v_pipeline_status)) f
    WHERE f.value:health = 'HEALTHY';
    
    -- By platform (from service accounts)
    SELECT OBJECT_AGG(PLATFORM, CNT) INTO v_by_platform
    FROM (
        SELECT 
            CASE 
                WHEN NAME LIKE 'AZURE%' THEN 'AZURE_DEVOPS'
                WHEN NAME LIKE 'GITHUB%' THEN 'GITHUB_ACTIONS'
                WHEN NAME LIKE 'GITLAB%' THEN 'GITLAB'
                ELSE 'OTHER'
            END AS PLATFORM,
            COUNT(*) AS CNT
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME LIKE '%_DEPLOYER'
          AND DELETED_ON IS NULL
        GROUP BY PLATFORM
    );
    
    -- Failing pipelines
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'pipeline_name', PIPELINE_NAME,
        'failure_count', FAIL_CNT,
        'last_failure', LAST_FAIL,
        'error_sample', ERROR_SAMPLE
    )) INTO v_failing_pipelines
    FROM (
        SELECT 
            PIPELINE_NAME,
            COUNT(*) AS FAIL_CNT,
            MAX(STARTED_AT) AS LAST_FAIL,
            MAX(ERROR_MESSAGE) AS ERROR_SAMPLE
        FROM DEVOPS_DEPLOYMENTS
        WHERE STATUS = 'FAILED'
          AND STARTED_AT >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
        GROUP BY PIPELINE_NAME
        HAVING COUNT(*) >= 2
        ORDER BY FAIL_CNT DESC
        LIMIT 10
    );
    
    -- Recent pipeline runs
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'deployment_id', DEPLOYMENT_ID,
        'pipeline', PIPELINE_NAME,
        'environment', TARGET_ENVIRONMENT,
        'database', DATABASE_NAME,
        'status', STATUS,
        'started_at', STARTED_AT,
        'duration_seconds', TIMESTAMPDIFF(SECOND, STARTED_AT, COALESCE(COMPLETED_AT, CURRENT_TIMESTAMP()))
    )) INTO v_recent_runs
    FROM DEVOPS_DEPLOYMENTS
    WHERE PIPELINE_NAME IS NOT NULL
    ORDER BY STARTED_AT DESC
    LIMIT 25;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'PIPELINE_STATUS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_pipelines', v_total_pipelines,
            'healthy_pipelines', v_healthy_count,
            'failing_pipelines', ARRAY_SIZE(COALESCE(v_failing_pipelines, ARRAY_CONSTRUCT())),
            'health_percentage', ROUND(v_healthy_count * 100.0 / NULLIF(v_total_pipelines, 0), 1)
        ),
        'overall_health', CASE 
            WHEN v_healthy_count = v_total_pipelines THEN 'ALL_HEALTHY'
            WHEN ARRAY_SIZE(COALESCE(v_failing_pipelines, ARRAY_CONSTRUCT())) > 0 THEN 'DEGRADED'
            ELSE 'HEALTHY'
        END,
        'by_platform', COALESCE(v_by_platform, OBJECT_CONSTRUCT()),
        'pipeline_status', COALESCE(v_pipeline_status, ARRAY_CONSTRUCT()),
        'failing_pipelines', COALESCE(v_failing_pipelines, ARRAY_CONSTRUCT()),
        'recent_runs', COALESCE(v_recent_runs, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 3: DEPLOYMENT TRACKING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Deployment Tracking Dashboard
 * 
 * Purpose: Track deployments across environments with trends
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_DEPLOYMENT_TRACKING_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_by_environment VARIANT;
    v_by_status VARIANT;
    v_daily_deployments ARRAY;
    v_recent_deployments ARRAY;
    v_deployment_velocity VARIANT;
    v_by_database ARRAY;
    v_total_deployments INTEGER;
    v_success_rate FLOAT;
BEGIN
    -- Total deployments
    SELECT COUNT(*), 
           ROUND(COUNT_IF(STATUS = 'SUCCESS') * 100.0 / NULLIF(COUNT(*), 0), 1)
    INTO v_total_deployments, v_success_rate
    FROM DEVOPS_DEPLOYMENTS
    WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP());
    
    -- By environment
    SELECT OBJECT_AGG(TARGET_ENVIRONMENT, OBJECT_CONSTRUCT(
        'total', TOTAL,
        'success', SUCCESS,
        'failed', FAILED,
        'in_progress', IN_PROG,
        'success_rate', ROUND(SUCCESS * 100.0 / NULLIF(TOTAL, 0), 1)
    )) INTO v_by_environment
    FROM (
        SELECT 
            TARGET_ENVIRONMENT,
            COUNT(*) AS TOTAL,
            COUNT_IF(STATUS = 'SUCCESS') AS SUCCESS,
            COUNT_IF(STATUS = 'FAILED') AS FAILED,
            COUNT_IF(STATUS = 'IN_PROGRESS') AS IN_PROG
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY TARGET_ENVIRONMENT
    );
    
    -- By status
    SELECT OBJECT_AGG(STATUS, CNT) INTO v_by_status
    FROM (
        SELECT STATUS, COUNT(*) AS CNT
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY STATUS
    );
    
    -- Daily deployments trend
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', DT,
        'total', TOTAL,
        'success', SUCCESS,
        'failed', FAILED
    )) INTO v_daily_deployments
    FROM (
        SELECT 
            DATE_TRUNC('DAY', STARTED_AT)::DATE AS DT,
            COUNT(*) AS TOTAL,
            COUNT_IF(STATUS = 'SUCCESS') AS SUCCESS,
            COUNT_IF(STATUS = 'FAILED') AS FAILED
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY DT
        ORDER BY DT
    );
    
    -- Recent deployments
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'deployment_id', DEPLOYMENT_ID,
        'type', DEPLOYMENT_TYPE,
        'environment', TARGET_ENVIRONMENT,
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'pipeline', PIPELINE_NAME,
        'status', STATUS,
        'deployed_by', DEPLOYED_BY,
        'started_at', STARTED_AT,
        'completed_at', COMPLETED_AT,
        'duration_seconds', TIMESTAMPDIFF(SECOND, STARTED_AT, COALESCE(COMPLETED_AT, CURRENT_TIMESTAMP()))
    )) INTO v_recent_deployments
    FROM DEVOPS_DEPLOYMENTS
    ORDER BY STARTED_AT DESC
    LIMIT 30;
    
    -- By database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'deployment_count', CNT,
        'last_deployment', LAST_DEPLOY,
        'success_rate', ROUND(SUCCESS * 100.0 / NULLIF(CNT, 0), 1)
    )) INTO v_by_database
    FROM (
        SELECT 
            DATABASE_NAME,
            COUNT(*) AS CNT,
            MAX(STARTED_AT) AS LAST_DEPLOY,
            COUNT_IF(STATUS = 'SUCCESS') AS SUCCESS
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
          AND DATABASE_NAME IS NOT NULL
        GROUP BY DATABASE_NAME
        ORDER BY CNT DESC
        LIMIT 15
    );
    
    -- Deployment velocity
    v_deployment_velocity := OBJECT_CONSTRUCT(
        'avg_per_day', ROUND(v_total_deployments * 1.0 / P_DAYS_BACK, 1),
        'avg_per_week', ROUND(v_total_deployments * 7.0 / P_DAYS_BACK, 1),
        'trend', CASE 
            WHEN v_total_deployments / P_DAYS_BACK > 5 THEN 'HIGH'
            WHEN v_total_deployments / P_DAYS_BACK > 2 THEN 'MODERATE'
            ELSE 'LOW'
        END
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'DEPLOYMENT_TRACKING',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS_BACK,
        'summary', OBJECT_CONSTRUCT(
            'total_deployments', v_total_deployments,
            'success_rate', v_success_rate,
            'avg_daily_deployments', ROUND(v_total_deployments * 1.0 / P_DAYS_BACK, 1)
        ),
        'velocity', v_deployment_velocity,
        'by_environment', COALESCE(v_by_environment, OBJECT_CONSTRUCT()),
        'by_status', COALESCE(v_by_status, OBJECT_CONSTRUCT()),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'daily_trend', COALESCE(v_daily_deployments, ARRAY_CONSTRUCT()),
        'recent_deployments', COALESCE(v_recent_deployments, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 4: RELEASE MANAGEMENT DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Release
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_LOG_RELEASE(
    P_VERSION VARCHAR,
    P_RELEASE_NAME VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR DEFAULT NULL,
    P_RELEASE_TYPE VARCHAR DEFAULT 'DEPLOYMENT',
    P_RELEASE_NOTES TEXT DEFAULT NULL,
    P_COMMIT_SHA VARCHAR DEFAULT NULL,
    P_BRANCH_NAME VARCHAR DEFAULT NULL,
    P_TAG_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_release_id VARCHAR;
    v_previous_version VARCHAR;
BEGIN
    v_release_id := UUID_STRING();
    
    -- Get previous version
    SELECT VERSION INTO v_previous_version
    FROM DEVOPS_RELEASES
    WHERE ENVIRONMENT = P_ENVIRONMENT
      AND DATABASE_NAME = P_DATABASE_NAME
      AND (P_SCHEMA_NAME IS NULL OR SCHEMA_NAME = P_SCHEMA_NAME)
      AND STATUS = 'DEPLOYED'
    ORDER BY DEPLOYED_AT DESC
    LIMIT 1;
    
    INSERT INTO DEVOPS_RELEASES (
        RELEASE_ID, VERSION, RELEASE_NAME, ENVIRONMENT, DATABASE_NAME,
        SCHEMA_NAME, RELEASE_TYPE, RELEASE_NOTES, COMMIT_SHA, BRANCH_NAME,
        TAG_NAME, PREVIOUS_VERSION
    ) VALUES (
        v_release_id, P_VERSION, P_RELEASE_NAME, P_ENVIRONMENT, P_DATABASE_NAME,
        P_SCHEMA_NAME, P_RELEASE_TYPE, P_RELEASE_NOTES, P_COMMIT_SHA, P_BRANCH_NAME,
        P_TAG_NAME, v_previous_version
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'release_id', v_release_id,
        'version', P_VERSION,
        'previous_version', v_previous_version,
        'environment', P_ENVIRONMENT
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Release Management Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_RELEASE_MANAGEMENT_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_current_versions ARRAY;
    v_recent_releases ARRAY;
    v_by_environment VARIANT;
    v_release_frequency ARRAY;
    v_rollbacks ARRAY;
BEGIN
    -- Current versions by environment/database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'environment', ENVIRONMENT,
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'current_version', VERSION,
        'release_name', RELEASE_NAME,
        'deployed_at', DEPLOYED_AT,
        'deployed_by', DEPLOYED_BY
    )) INTO v_current_versions
    FROM (
        SELECT *
        FROM DEVOPS_RELEASES
        WHERE STATUS = 'DEPLOYED'
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY ENVIRONMENT, DATABASE_NAME, COALESCE(SCHEMA_NAME, '')
            ORDER BY DEPLOYED_AT DESC
        ) = 1
        ORDER BY ENVIRONMENT, DATABASE_NAME
    );
    
    -- Recent releases
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'release_id', RELEASE_ID,
        'version', VERSION,
        'release_name', RELEASE_NAME,
        'environment', ENVIRONMENT,
        'database', DATABASE_NAME,
        'release_type', RELEASE_TYPE,
        'deployed_by', DEPLOYED_BY,
        'deployed_at', DEPLOYED_AT,
        'commit', COMMIT_SHA,
        'tag', TAG_NAME
    )) INTO v_recent_releases
    FROM DEVOPS_RELEASES
    ORDER BY DEPLOYED_AT DESC
    LIMIT 25;
    
    -- By environment
    SELECT OBJECT_AGG(ENVIRONMENT, OBJECT_CONSTRUCT(
        'total_releases', TOTAL,
        'unique_databases', DBS,
        'latest_release', LATEST
    )) INTO v_by_environment
    FROM (
        SELECT 
            ENVIRONMENT,
            COUNT(*) AS TOTAL,
            COUNT(DISTINCT DATABASE_NAME) AS DBS,
            MAX(DEPLOYED_AT) AS LATEST
        FROM DEVOPS_RELEASES
        WHERE DEPLOYED_AT >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
        GROUP BY ENVIRONMENT
    );
    
    -- Release frequency (weekly)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'week', WK,
        'releases', CNT,
        'unique_versions', VERSIONS
    )) INTO v_release_frequency
    FROM (
        SELECT 
            DATE_TRUNC('WEEK', DEPLOYED_AT)::DATE AS WK,
            COUNT(*) AS CNT,
            COUNT(DISTINCT VERSION) AS VERSIONS
        FROM DEVOPS_RELEASES
        WHERE DEPLOYED_AT >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
        GROUP BY WK
        ORDER BY WK
    );
    
    -- Rollbacks
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'release_id', RELEASE_ID,
        'version', VERSION,
        'environment', ENVIRONMENT,
        'database', DATABASE_NAME,
        'rolled_back_from', PREVIOUS_VERSION,
        'deployed_at', DEPLOYED_AT,
        'deployed_by', DEPLOYED_BY
    )) INTO v_rollbacks
    FROM DEVOPS_RELEASES
    WHERE ROLLBACK_OF IS NOT NULL
      AND DEPLOYED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    ORDER BY DEPLOYED_AT DESC;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'RELEASE_MANAGEMENT',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_releases_90d', (SELECT COUNT(*) FROM DEVOPS_RELEASES WHERE DEPLOYED_AT >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())),
            'rollbacks_30d', ARRAY_SIZE(COALESCE(v_rollbacks, ARRAY_CONSTRUCT())),
            'environments_with_releases', (SELECT COUNT(DISTINCT ENVIRONMENT) FROM DEVOPS_RELEASES)
        ),
        'current_versions', COALESCE(v_current_versions, ARRAY_CONSTRUCT()),
        'recent_releases', COALESCE(v_recent_releases, ARRAY_CONSTRUCT()),
        'by_environment', COALESCE(v_by_environment, OBJECT_CONSTRUCT()),
        'release_frequency', COALESCE(v_release_frequency, ARRAY_CONSTRUCT()),
        'rollbacks', COALESCE(v_rollbacks, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 5: GIT INTEGRATION DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Git Integration Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_GIT_INTEGRATION_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_repositories ARRAY;
    v_recent_deployments_from_git ARRAY;
    v_branch_activity ARRAY;
    v_commit_stats VARIANT;
BEGIN
    -- Registered repositories
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'repo_name', REPO_NAME,
        'origin_url', ORIGIN_URL,
        'default_branch', DEFAULT_BRANCH,
        'environments', ENVIRONMENTS,
        'last_sync', LAST_SYNC_AT,
        'created_by', CREATED_BY
    )) INTO v_repositories
    FROM DEVOPS_GIT_REPOSITORIES
    ORDER BY CREATED_AT DESC;
    
    -- Recent deployments from Git
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'deployment_id', DEPLOYMENT_ID,
        'repository', METADATA:file_path::VARCHAR,
        'branch', BRANCH_NAME,
        'commit', COMMIT_SHA,
        'environment', TARGET_ENVIRONMENT,
        'status', STATUS,
        'deployed_at', STARTED_AT
    )) INTO v_recent_deployments_from_git
    FROM DEVOPS_DEPLOYMENTS
    WHERE DEPLOYMENT_TYPE = 'GIT_DEPLOY'
      AND STARTED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
    ORDER BY STARTED_AT DESC
    LIMIT 25;
    
    -- Branch activity
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'branch', BRANCH_NAME,
        'deployment_count', CNT,
        'last_deployment', LAST_DEPLOY,
        'environments', ENVS
    )) INTO v_branch_activity
    FROM (
        SELECT 
            BRANCH_NAME,
            COUNT(*) AS CNT,
            MAX(STARTED_AT) AS LAST_DEPLOY,
            ARRAY_AGG(DISTINCT TARGET_ENVIRONMENT) AS ENVS
        FROM DEVOPS_DEPLOYMENTS
        WHERE BRANCH_NAME IS NOT NULL
          AND STARTED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
        GROUP BY BRANCH_NAME
        ORDER BY CNT DESC
        LIMIT 15
    );
    
    -- Commit statistics
    SELECT OBJECT_CONSTRUCT(
        'total_commits_deployed', COUNT(DISTINCT COMMIT_SHA),
        'deployments_with_commit', COUNT_IF(COMMIT_SHA IS NOT NULL),
        'deployments_without_commit', COUNT_IF(COMMIT_SHA IS NULL)
    ) INTO v_commit_stats
    FROM DEVOPS_DEPLOYMENTS
    WHERE STARTED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP());
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'GIT_INTEGRATION',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'registered_repositories', ARRAY_SIZE(COALESCE(v_repositories, ARRAY_CONSTRUCT())),
            'git_deployments_30d', ARRAY_SIZE(COALESCE(v_recent_deployments_from_git, ARRAY_CONSTRUCT())),
            'active_branches', ARRAY_SIZE(COALESCE(v_branch_activity, ARRAY_CONSTRUCT()))
        ),
        'commit_stats', COALESCE(v_commit_stats, OBJECT_CONSTRUCT()),
        'repositories', COALESCE(v_repositories, ARRAY_CONSTRUCT()),
        'recent_git_deployments', COALESCE(v_recent_deployments_from_git, ARRAY_CONSTRUCT()),
        'branch_activity', COALESCE(v_branch_activity, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 6: CHANGE ANALYTICS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Change
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_LOG_CHANGE(
    P_CHANGE_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_OBJECT_TYPE VARCHAR,
    P_OBJECT_NAME VARCHAR,
    P_DESCRIPTION TEXT DEFAULT NULL,
    P_DEPLOYMENT_ID VARCHAR DEFAULT NULL,
    P_RELEASE_ID VARCHAR DEFAULT NULL,
    P_IS_BREAKING BOOLEAN DEFAULT FALSE
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_change_id VARCHAR;
BEGIN
    v_change_id := UUID_STRING();
    
    INSERT INTO DEVOPS_CHANGE_LOG (
        CHANGE_ID, CHANGE_TYPE, ENVIRONMENT, DATABASE_NAME, SCHEMA_NAME,
        OBJECT_TYPE, OBJECT_NAME, CHANGE_DESCRIPTION, DEPLOYMENT_ID,
        RELEASE_ID, IS_BREAKING_CHANGE
    ) VALUES (
        v_change_id, P_CHANGE_TYPE, P_ENVIRONMENT, P_DATABASE_NAME, P_SCHEMA_NAME,
        P_OBJECT_TYPE, P_OBJECT_NAME, P_DESCRIPTION, P_DEPLOYMENT_ID,
        P_RELEASE_ID, P_IS_BREAKING
    );
    
    RETURN v_change_id;
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Change Analytics Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_CHANGE_ANALYTICS_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_by_type VARIANT;
    v_by_environment VARIANT;
    v_by_object_type VARIANT;
    v_daily_changes ARRAY;
    v_breaking_changes ARRAY;
    v_top_changed_objects ARRAY;
    v_change_velocity VARIANT;
    v_total_changes INTEGER;
BEGIN
    -- Total changes
    SELECT COUNT(*) INTO v_total_changes
    FROM DEVOPS_CHANGE_LOG
    WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP());
    
    -- By change type
    SELECT OBJECT_AGG(CHANGE_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT CHANGE_TYPE, COUNT(*) AS CNT
        FROM DEVOPS_CHANGE_LOG
        WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY CHANGE_TYPE
    );
    
    -- By environment
    SELECT OBJECT_AGG(ENVIRONMENT, CNT) INTO v_by_environment
    FROM (
        SELECT ENVIRONMENT, COUNT(*) AS CNT
        FROM DEVOPS_CHANGE_LOG
        WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY ENVIRONMENT
    );
    
    -- By object type
    SELECT OBJECT_AGG(OBJECT_TYPE, CNT) INTO v_by_object_type
    FROM (
        SELECT OBJECT_TYPE, COUNT(*) AS CNT
        FROM DEVOPS_CHANGE_LOG
        WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY OBJECT_TYPE
    );
    
    -- Daily changes
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', DT,
        'changes', CNT,
        'breaking', BREAKING
    )) INTO v_daily_changes
    FROM (
        SELECT 
            DATE_TRUNC('DAY', CHANGED_AT)::DATE AS DT,
            COUNT(*) AS CNT,
            COUNT_IF(IS_BREAKING_CHANGE) AS BREAKING
        FROM DEVOPS_CHANGE_LOG
        WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY DT
        ORDER BY DT
    );
    
    -- Breaking changes
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'change_id', CHANGE_ID,
        'type', CHANGE_TYPE,
        'environment', ENVIRONMENT,
        'object', OBJECT_TYPE || ': ' || OBJECT_NAME,
        'description', CHANGE_DESCRIPTION,
        'changed_by', CHANGED_BY,
        'changed_at', CHANGED_AT
    )) INTO v_breaking_changes
    FROM DEVOPS_CHANGE_LOG
    WHERE IS_BREAKING_CHANGE = TRUE
      AND CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
    ORDER BY CHANGED_AT DESC
    LIMIT 20;
    
    -- Most changed objects
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'object', OBJECT_TYPE || ': ' || OBJECT_NAME,
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'change_count', CNT,
        'last_change', LAST_CHANGE
    )) INTO v_top_changed_objects
    FROM (
        SELECT 
            OBJECT_TYPE, OBJECT_NAME, DATABASE_NAME, SCHEMA_NAME,
            COUNT(*) AS CNT,
            MAX(CHANGED_AT) AS LAST_CHANGE
        FROM DEVOPS_CHANGE_LOG
        WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY OBJECT_TYPE, OBJECT_NAME, DATABASE_NAME, SCHEMA_NAME
        ORDER BY CNT DESC
        LIMIT 15
    );
    
    -- Change velocity
    v_change_velocity := OBJECT_CONSTRUCT(
        'avg_per_day', ROUND(v_total_changes * 1.0 / P_DAYS_BACK, 1),
        'avg_per_week', ROUND(v_total_changes * 7.0 / P_DAYS_BACK, 1),
        'breaking_percentage', ROUND(
            (SELECT COUNT_IF(IS_BREAKING_CHANGE) * 100.0 / NULLIF(COUNT(*), 0)
             FROM DEVOPS_CHANGE_LOG
             WHERE CHANGED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())), 1
        )
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CHANGE_ANALYTICS',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS_BACK,
        'summary', OBJECT_CONSTRUCT(
            'total_changes', v_total_changes,
            'breaking_changes', ARRAY_SIZE(COALESCE(v_breaking_changes, ARRAY_CONSTRUCT())),
            'unique_objects_changed', ARRAY_SIZE(COALESCE(v_top_changed_objects, ARRAY_CONSTRUCT()))
        ),
        'velocity', v_change_velocity,
        'by_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'by_environment', COALESCE(v_by_environment, OBJECT_CONSTRUCT()),
        'by_object_type', COALESCE(v_by_object_type, OBJECT_CONSTRUCT()),
        'daily_trend', COALESCE(v_daily_changes, ARRAY_CONSTRUCT()),
        'breaking_changes', COALESCE(v_breaking_changes, ARRAY_CONSTRUCT()),
        'top_changed_objects', COALESCE(v_top_changed_objects, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 7: FAILURE ANALYSIS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Deployment Failure Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_DEPLOYMENT_FAILURE_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_failure_rate FLOAT;
    v_by_environment VARIANT;
    v_by_pipeline ARRAY;
    v_by_error_type ARRAY;
    v_recent_failures ARRAY;
    v_failure_trend ARRAY;
    v_mttr VARIANT;
BEGIN
    -- Overall failure rate
    SELECT ROUND(COUNT_IF(STATUS = 'FAILED') * 100.0 / NULLIF(COUNT(*), 0), 2)
    INTO v_failure_rate
    FROM DEVOPS_DEPLOYMENTS
    WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP());
    
    -- By environment
    SELECT OBJECT_AGG(TARGET_ENVIRONMENT, OBJECT_CONSTRUCT(
        'total', TOTAL,
        'failed', FAILED,
        'failure_rate', ROUND(FAILED * 100.0 / NULLIF(TOTAL, 0), 2)
    )) INTO v_by_environment
    FROM (
        SELECT 
            TARGET_ENVIRONMENT,
            COUNT(*) AS TOTAL,
            COUNT_IF(STATUS = 'FAILED') AS FAILED
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY TARGET_ENVIRONMENT
    );
    
    -- By pipeline
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'pipeline', PIPELINE_NAME,
        'total', TOTAL,
        'failed', FAILED,
        'failure_rate', ROUND(FAILED * 100.0 / NULLIF(TOTAL, 0), 2),
        'last_failure', LAST_FAIL
    )) INTO v_by_pipeline
    FROM (
        SELECT 
            PIPELINE_NAME,
            COUNT(*) AS TOTAL,
            COUNT_IF(STATUS = 'FAILED') AS FAILED,
            MAX(CASE WHEN STATUS = 'FAILED' THEN STARTED_AT END) AS LAST_FAIL
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
          AND PIPELINE_NAME IS NOT NULL
        GROUP BY PIPELINE_NAME
        HAVING COUNT_IF(STATUS = 'FAILED') > 0
        ORDER BY FAILED DESC
        LIMIT 15
    );
    
    -- Recent failures with details
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'deployment_id', DEPLOYMENT_ID,
        'pipeline', PIPELINE_NAME,
        'environment', TARGET_ENVIRONMENT,
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'error', ERROR_MESSAGE,
        'deployed_by', DEPLOYED_BY,
        'started_at', STARTED_AT
    )) INTO v_recent_failures
    FROM DEVOPS_DEPLOYMENTS
    WHERE STATUS = 'FAILED'
      AND STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
    ORDER BY STARTED_AT DESC
    LIMIT 25;
    
    -- Failure trend
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', DT,
        'total', TOTAL,
        'failed', FAILED,
        'failure_rate', ROUND(FAILED * 100.0 / NULLIF(TOTAL, 0), 2)
    )) INTO v_failure_trend
    FROM (
        SELECT 
            DATE_TRUNC('DAY', STARTED_AT)::DATE AS DT,
            COUNT(*) AS TOTAL,
            COUNT_IF(STATUS = 'FAILED') AS FAILED
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY DT
        ORDER BY DT
    );
    
    -- Mean time to recovery (simplified)
    v_mttr := OBJECT_CONSTRUCT(
        'note', 'MTTR calculation requires success after failure tracking',
        'avg_deployment_duration_seconds', (
            SELECT ROUND(AVG(TIMESTAMPDIFF(SECOND, STARTED_AT, COMPLETED_AT)), 0)
            FROM DEVOPS_DEPLOYMENTS
            WHERE STATUS = 'SUCCESS'
              AND COMPLETED_AT IS NOT NULL
              AND STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        )
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'DEPLOYMENT_FAILURE',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS_BACK,
        'summary', OBJECT_CONSTRUCT(
            'overall_failure_rate', v_failure_rate,
            'total_failures', (
                SELECT COUNT(*) FROM DEVOPS_DEPLOYMENTS 
                WHERE STATUS = 'FAILED' 
                  AND STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
            ),
            'pipelines_with_failures', ARRAY_SIZE(COALESCE(v_by_pipeline, ARRAY_CONSTRUCT()))
        ),
        'health_status', CASE 
            WHEN v_failure_rate > 20 THEN 'CRITICAL'
            WHEN v_failure_rate > 10 THEN 'WARNING'
            WHEN v_failure_rate > 5 THEN 'ATTENTION'
            ELSE 'HEALTHY'
        END,
        'by_environment', COALESCE(v_by_environment, OBJECT_CONSTRUCT()),
        'by_pipeline', COALESCE(v_by_pipeline, ARRAY_CONSTRUCT()),
        'failure_trend', COALESCE(v_failure_trend, ARRAY_CONSTRUCT()),
        'recent_failures', COALESCE(v_recent_failures, ARRAY_CONSTRUCT()),
        'mttr', v_mttr
    );
END;
$$;

-- #############################################################################
-- SECTION 8: UNIFIED DEVOPS MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: DevOps Monitoring Dashboard (Unified)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.RBAC_DEVOPS_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_pipeline_dashboard VARIANT;
    v_deployment_dashboard VARIANT;
    v_release_dashboard VARIANT;
    v_git_dashboard VARIANT;
    v_failure_dashboard VARIANT;
    v_overall_health VARCHAR;
    v_alerts ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Gather all dashboards
    CALL ADMIN.DEVOPS.RBAC_PIPELINE_STATUS_DASHBOARD() INTO v_pipeline_dashboard;
    CALL ADMIN.DEVOPS.RBAC_DEPLOYMENT_TRACKING_DASHBOARD(7) INTO v_deployment_dashboard;
    CALL ADMIN.DEVOPS.RBAC_RELEASE_MANAGEMENT_DASHBOARD() INTO v_release_dashboard;
    CALL ADMIN.DEVOPS.RBAC_GIT_INTEGRATION_DASHBOARD() INTO v_git_dashboard;
    CALL ADMIN.DEVOPS.RBAC_DEPLOYMENT_FAILURE_DASHBOARD(7) INTO v_failure_dashboard;
    
    -- Determine overall health
    IF (v_failure_dashboard:health_status = 'CRITICAL') THEN
        v_overall_health := 'CRITICAL';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'CRITICAL',
            'message', 'High deployment failure rate detected',
            'action', 'Review recent failures immediately'
        ));
    ELSEIF (v_pipeline_dashboard:overall_health = 'DEGRADED') THEN
        v_overall_health := 'WARNING';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', 'Some pipelines are failing',
            'action', 'Check failing pipelines'
        ));
    ELSEIF (v_failure_dashboard:health_status = 'WARNING') THEN
        v_overall_health := 'WARNING';
    ELSE
        v_overall_health := 'HEALTHY';
    END IF;
    
    -- Add rollback alert if any recent rollbacks
    IF (v_release_dashboard:summary:rollbacks_30d > 0) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', v_release_dashboard:summary:rollbacks_30d || ' rollbacks in the last 30 days',
            'action', 'Review rollback reasons'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'DEVOPS_MONITORING_UNIFIED',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall_health', v_overall_health,
        'alerts', v_alerts,
        'quick_stats', OBJECT_CONSTRUCT(
            'deployments_7d', v_deployment_dashboard:summary:total_deployments,
            'success_rate', v_deployment_dashboard:summary:success_rate,
            'active_pipelines', v_pipeline_dashboard:summary:total_pipelines,
            'healthy_pipelines', v_pipeline_dashboard:summary:healthy_pipelines,
            'releases_90d', v_release_dashboard:summary:total_releases_90d,
            'rollbacks_30d', v_release_dashboard:summary:rollbacks_30d,
            'git_repos', v_git_dashboard:summary:registered_repositories
        ),
        'pipelines', v_pipeline_dashboard,
        'deployments', v_deployment_dashboard,
        'releases', v_release_dashboard,
        'git', v_git_dashboard,
        'failures', v_failure_dashboard
    );
END;
$$;

-- #############################################################################
-- SECTION 9: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_PIPELINE_STATUS_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_DEPLOYMENT_TRACKING_DASHBOARD(INTEGER) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_LOG_RELEASE(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_RELEASE_MANAGEMENT_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_GIT_INTEGRATION_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_LOG_CHANGE(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_CHANGE_ANALYTICS_DASHBOARD(INTEGER) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_DEPLOYMENT_FAILURE_DASHBOARD(INTEGER) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_DEVOPS_MONITORING_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;

-- Also grant to Security Admin for oversight
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.RBAC_DEVOPS_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
