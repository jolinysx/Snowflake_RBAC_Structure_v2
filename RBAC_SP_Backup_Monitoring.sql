/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of backup operations including:
 *          - Backup health and status
 *          - Storage consumption and costs
 *          - Time Travel coverage
 *          - Compliance reporting
 *          - Backup history and trends
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          BACKUP
 *   Object Type:     PROCEDURES (~6)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and BACKUP schema must exist
 *     - RBAC_SP_Backup_Management.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT: ADMIN.BACKUP schema
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA BACKUP;

-- #############################################################################
-- SECTION 1: BACKUP STATUS DASHBOARD
-- #############################################################################

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STATUS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_backups INTEGER;
    v_active_backups INTEGER;
    v_expiring_soon INTEGER;
    v_by_type VARIANT;
    v_by_tag VARIANT;
    v_recent_backups VARIANT;
    v_recent_restores VARIANT;
    v_policy_status VARIANT;
BEGIN
    -- Count backups
    SELECT 
        COUNT(*),
        COUNT_IF(STATUS = 'ACTIVE'),
        COUNT_IF(STATUS = 'ACTIVE' AND EXPIRES_AT BETWEEN CURRENT_TIMESTAMP() AND DATEADD(DAY, 7, CURRENT_TIMESTAMP()))
    INTO v_total_backups, v_active_backups, v_expiring_soon
    FROM BACKUP_CATALOG;
    
    -- By type
    SELECT OBJECT_AGG(BACKUP_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT BACKUP_TYPE, COUNT(*) AS CNT
        FROM BACKUP_CATALOG WHERE STATUS = 'ACTIVE'
        GROUP BY BACKUP_TYPE
    );
    
    -- By tag
    SELECT OBJECT_AGG(BACKUP_TAG, CNT) INTO v_by_tag
    FROM (
        SELECT BACKUP_TAG, COUNT(*) AS CNT
        FROM BACKUP_CATALOG WHERE STATUS = 'ACTIVE'
        GROUP BY BACKUP_TAG
    );
    
    -- Recent backups
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'backup_name', BACKUP_NAME,
        'backup_type', BACKUP_TYPE,
        'source', SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, '') || COALESCE('.' || SOURCE_TABLE, ''),
        'tag', BACKUP_TAG,
        'timestamp', BACKUP_TIMESTAMP,
        'expires_at', EXPIRES_AT
    )) WITHIN GROUP (ORDER BY BACKUP_TIMESTAMP DESC) INTO v_recent_backups
    FROM (
        SELECT * FROM BACKUP_CATALOG 
        WHERE STATUS = 'ACTIVE'
        LIMIT 10
    );
    
    -- Recent restores
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'restore_id', RESTORE_ID,
        'backup_id', BACKUP_ID,
        'restore_type', RESTORE_TYPE,
        'method', RESTORE_METHOD,
        'target', TARGET_OBJECT,
        'status', STATUS,
        'restored_by', RESTORED_BY,
        'timestamp', STARTED_AT
    )) WITHIN GROUP (ORDER BY STARTED_AT DESC) INTO v_recent_restores
    FROM (
        SELECT * FROM BACKUP_RESTORE_HISTORY
        LIMIT 10
    );
    
    -- Policy status
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_name', POLICY_NAME,
        'backup_type', BACKUP_TYPE,
        'frequency', BACKUP_FREQUENCY,
        'is_active', IS_ACTIVE,
        'last_backup', LAST_BACKUP_AT,
        'status', CASE 
            WHEN NOT IS_ACTIVE THEN 'PAUSED'
            WHEN LAST_BACKUP_AT IS NULL THEN 'NEVER_RUN'
            WHEN BACKUP_FREQUENCY = 'HOURLY' AND LAST_BACKUP_AT < DATEADD(HOUR, -2, CURRENT_TIMESTAMP()) THEN 'OVERDUE'
            WHEN BACKUP_FREQUENCY = 'DAILY' AND LAST_BACKUP_AT < DATEADD(DAY, -2, CURRENT_TIMESTAMP()) THEN 'OVERDUE'
            WHEN BACKUP_FREQUENCY = 'WEEKLY' AND LAST_BACKUP_AT < DATEADD(DAY, -8, CURRENT_TIMESTAMP()) THEN 'OVERDUE'
            ELSE 'OK'
        END
    )) INTO v_policy_status
    FROM BACKUP_POLICIES;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_STATUS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_backups', v_total_backups,
            'active_backups', v_active_backups,
            'expiring_in_7_days', v_expiring_soon
        ),
        'by_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'by_tag', COALESCE(v_by_tag, OBJECT_CONSTRUCT()),
        'recent_backups', COALESCE(v_recent_backups, ARRAY_CONSTRUCT()),
        'recent_restores', COALESCE(v_recent_restores, ARRAY_CONSTRUCT()),
        'policy_status', COALESCE(v_policy_status, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 2: BACKUP STORAGE COSTS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Storage Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STORAGE_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_by_database VARIANT;
    v_by_type VARIANT;
    v_by_tag VARIANT;
    v_largest_backups VARIANT;
    v_total_size NUMBER;
    v_estimated_cost NUMBER;
BEGIN
    -- Storage by source database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', SOURCE_DATABASE,
        'backup_count', CNT,
        'total_size_gb', ROUND(TOTAL_SIZE / 1024 / 1024 / 1024, 2)
    )) WITHIN GROUP (ORDER BY TOTAL_SIZE DESC) INTO v_by_database
    FROM (
        SELECT SOURCE_DATABASE, COUNT(*) AS CNT, SUM(COALESCE(SIZE_BYTES, 0)) AS TOTAL_SIZE
        FROM BACKUP_CATALOG
        WHERE STATUS = 'ACTIVE'
        GROUP BY SOURCE_DATABASE
    );
    
    -- Storage by backup type
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'backup_type', BACKUP_TYPE,
        'backup_count', CNT,
        'total_size_gb', ROUND(TOTAL_SIZE / 1024 / 1024 / 1024, 2)
    )) INTO v_by_type
    FROM (
        SELECT BACKUP_TYPE, COUNT(*) AS CNT, SUM(COALESCE(SIZE_BYTES, 0)) AS TOTAL_SIZE
        FROM BACKUP_CATALOG
        WHERE STATUS = 'ACTIVE'
        GROUP BY BACKUP_TYPE
    );
    
    -- Storage by tag
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'tag', BACKUP_TAG,
        'backup_count', CNT,
        'total_size_gb', ROUND(TOTAL_SIZE / 1024 / 1024 / 1024, 2)
    )) INTO v_by_tag
    FROM (
        SELECT BACKUP_TAG, COUNT(*) AS CNT, SUM(COALESCE(SIZE_BYTES, 0)) AS TOTAL_SIZE
        FROM BACKUP_CATALOG
        WHERE STATUS = 'ACTIVE'
        GROUP BY BACKUP_TAG
    );
    
    -- Largest backups
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'backup_name', BACKUP_NAME,
        'source', SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, ''),
        'size_gb', ROUND(SIZE_BYTES / 1024 / 1024 / 1024, 2),
        'tag', BACKUP_TAG,
        'expires_at', EXPIRES_AT
    )) WITHIN GROUP (ORDER BY SIZE_BYTES DESC) INTO v_largest_backups
    FROM (
        SELECT * FROM BACKUP_CATALOG
        WHERE STATUS = 'ACTIVE' AND SIZE_BYTES IS NOT NULL
        LIMIT 10
    );
    
    -- Total size and estimated cost
    SELECT SUM(COALESCE(SIZE_BYTES, 0)) INTO v_total_size
    FROM BACKUP_CATALOG WHERE STATUS = 'ACTIVE';
    
    -- Estimate at $23/TB/month (Snowflake on-demand storage pricing)
    v_estimated_cost := ROUND((v_total_size / 1024 / 1024 / 1024 / 1024) * 23, 2);
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_STORAGE',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_size_gb', ROUND(v_total_size / 1024 / 1024 / 1024, 2),
            'total_size_tb', ROUND(v_total_size / 1024 / 1024 / 1024 / 1024, 3),
            'estimated_monthly_cost_usd', v_estimated_cost
        ),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'by_type', COALESCE(v_by_type, ARRAY_CONSTRUCT()),
        'by_tag', COALESCE(v_by_tag, ARRAY_CONSTRUCT()),
        'largest_backups', COALESCE(v_largest_backups, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 3: TIME TRAVEL COVERAGE
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Time Travel Coverage Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_TIME_TRAVEL_COVERAGE_DASHBOARD(
    P_DATABASE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_coverage_summary VARIANT;
    v_by_database VARIANT;
    v_low_retention VARIANT;
    v_no_retention VARIANT;
    v_recommendations ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Coverage by database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'retention_time', RETENTION_TIME,
        'table_count', TABLE_COUNT,
        'coverage_status', CASE 
            WHEN RETENTION_TIME >= 7 THEN 'GOOD'
            WHEN RETENTION_TIME >= 1 THEN 'MINIMAL'
            ELSE 'NONE'
        END
    )) WITHIN GROUP (ORDER BY DATABASE_NAME) INTO v_by_database
    FROM (
        SELECT 
            d.DATABASE_NAME,
            d.RETENTION_TIME,
            COUNT(t.TABLE_NAME) AS TABLE_COUNT
        FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES d
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TABLES t 
            ON d.DATABASE_NAME = t.TABLE_CATALOG AND t.DELETED IS NULL
        WHERE d.DELETED IS NULL
          AND d.DATABASE_NAME NOT IN ('SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA')
          AND (P_DATABASE IS NULL OR d.DATABASE_NAME = P_DATABASE)
        GROUP BY d.DATABASE_NAME, d.RETENTION_TIME
    );
    
    -- Tables with low retention (1 day)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', TABLE_CATALOG,
        'schema', TABLE_SCHEMA,
        'table', TABLE_NAME,
        'retention_time', RETENTION_TIME
    )) INTO v_low_retention
    FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
    WHERE DELETED IS NULL
      AND RETENTION_TIME = 1
      AND TABLE_CATALOG NOT IN ('SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA')
      AND (P_DATABASE IS NULL OR TABLE_CATALOG = P_DATABASE)
    LIMIT 50;
    
    -- Tables with zero retention
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', TABLE_CATALOG,
        'schema', TABLE_SCHEMA,
        'table', TABLE_NAME
    )) INTO v_no_retention
    FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
    WHERE DELETED IS NULL
      AND RETENTION_TIME = 0
      AND TABLE_CATALOG NOT IN ('SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA')
      AND (P_DATABASE IS NULL OR TABLE_CATALOG = P_DATABASE)
    LIMIT 50;
    
    -- Generate recommendations
    IF (ARRAY_SIZE(COALESCE(v_no_retention, ARRAY_CONSTRUCT())) > 0) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, OBJECT_CONSTRUCT(
            'priority', 'HIGH',
            'issue', 'Tables with zero Time Travel retention',
            'count', ARRAY_SIZE(v_no_retention),
            'action', 'ALTER TABLE ... SET DATA_RETENTION_TIME_IN_DAYS = 1;'
        ));
    END IF;
    
    IF (ARRAY_SIZE(COALESCE(v_low_retention, ARRAY_CONSTRUCT())) > 10) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, OBJECT_CONSTRUCT(
            'priority', 'MEDIUM',
            'issue', 'Many tables with minimal Time Travel (1 day)',
            'count', ARRAY_SIZE(v_low_retention),
            'action', 'Consider increasing retention for critical tables'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'TIME_TRAVEL_COVERAGE',
        'generated_at', CURRENT_TIMESTAMP(),
        'filter', OBJECT_CONSTRUCT('database', P_DATABASE),
        'summary', OBJECT_CONSTRUCT(
            'databases_analyzed', ARRAY_SIZE(COALESCE(v_by_database, ARRAY_CONSTRUCT())),
            'tables_with_low_retention', ARRAY_SIZE(COALESCE(v_low_retention, ARRAY_CONSTRUCT())),
            'tables_with_no_retention', ARRAY_SIZE(COALESCE(v_no_retention, ARRAY_CONSTRUCT()))
        ),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'low_retention_tables', COALESCE(v_low_retention, ARRAY_CONSTRUCT()),
        'no_retention_tables', COALESCE(v_no_retention, ARRAY_CONSTRUCT()),
        'recommendations', v_recommendations
    );
END;
$$;

-- #############################################################################
-- SECTION 4: BACKUP COMPLIANCE REPORT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Compliance Report
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_COMPLIANCE_REPORT()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_compliance_score INTEGER := 0;
    v_max_score INTEGER := 100;
    v_checks ARRAY := ARRAY_CONSTRUCT();
    v_policy_coverage INTEGER;
    v_recent_backup_count INTEGER;
    v_failed_jobs INTEGER;
    v_databases_without_backup VARIANT;
    v_overdue_policies VARIANT;
BEGIN
    -- Check 1: Backup policy coverage (25 points)
    SELECT COUNT(*) INTO v_policy_coverage FROM BACKUP_POLICIES WHERE IS_ACTIVE = TRUE;
    LET v_policy_score INTEGER := LEAST(v_policy_coverage * 5, 25);
    v_compliance_score := v_compliance_score + v_policy_score;
    v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
        'check', 'BACKUP_POLICIES',
        'score', v_policy_score,
        'max_score', 25,
        'metric', v_policy_coverage || ' active policies',
        'status', CASE WHEN v_policy_score >= 20 THEN 'GOOD' WHEN v_policy_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    
    -- Check 2: Recent backup activity (25 points)
    SELECT COUNT(*) INTO v_recent_backup_count
    FROM BACKUP_CATALOG
    WHERE BACKUP_TIMESTAMP > DATEADD(DAY, -7, CURRENT_TIMESTAMP()) AND STATUS = 'ACTIVE';
    LET v_recent_score INTEGER := LEAST(v_recent_backup_count * 3, 25);
    v_compliance_score := v_compliance_score + v_recent_score;
    v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
        'check', 'RECENT_BACKUPS',
        'score', v_recent_score,
        'max_score', 25,
        'metric', v_recent_backup_count || ' backups in last 7 days',
        'status', CASE WHEN v_recent_score >= 20 THEN 'GOOD' WHEN v_recent_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    
    -- Check 3: Job success rate (25 points)
    SELECT COUNT_IF(STATUS = 'FAILED') INTO v_failed_jobs
    FROM BACKUP_JOBS
    WHERE STARTED_AT > DATEADD(DAY, -30, CURRENT_TIMESTAMP());
    LET v_job_score INTEGER := CASE WHEN v_failed_jobs = 0 THEN 25 WHEN v_failed_jobs <= 2 THEN 20 WHEN v_failed_jobs <= 5 THEN 15 ELSE 10 END;
    v_compliance_score := v_compliance_score + v_job_score;
    v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
        'check', 'JOB_SUCCESS_RATE',
        'score', v_job_score,
        'max_score', 25,
        'metric', v_failed_jobs || ' failed jobs in last 30 days',
        'status', CASE WHEN v_job_score >= 20 THEN 'GOOD' WHEN v_job_score >= 15 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    
    -- Check 4: Retention compliance (25 points)
    SELECT COUNT(*) INTO v_policy_coverage
    FROM BACKUP_CATALOG
    WHERE STATUS = 'ACTIVE' AND EXPIRES_AT > DATEADD(DAY, 7, CURRENT_TIMESTAMP());
    LET v_retention_score INTEGER := LEAST(v_policy_coverage * 2, 25);
    v_compliance_score := v_compliance_score + v_retention_score;
    v_checks := ARRAY_APPEND(v_checks, OBJECT_CONSTRUCT(
        'check', 'RETENTION_COMPLIANCE',
        'score', v_retention_score,
        'max_score', 25,
        'metric', v_policy_coverage || ' backups with 7+ days retention',
        'status', CASE WHEN v_retention_score >= 20 THEN 'GOOD' WHEN v_retention_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    
    -- Find databases without backups
    SELECT ARRAY_AGG(DATABASE_NAME) INTO v_databases_without_backup
    FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES
    WHERE DELETED IS NULL
      AND DATABASE_NAME NOT IN ('SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA', 'ADMIN')
      AND DATABASE_NAME NOT LIKE '%_BKP_%'
      AND DATABASE_NAME NOT IN (SELECT DISTINCT SOURCE_DATABASE FROM BACKUP_CATALOG WHERE STATUS = 'ACTIVE');
    
    -- Find overdue policies
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_name', POLICY_NAME,
        'frequency', BACKUP_FREQUENCY,
        'last_backup', LAST_BACKUP_AT,
        'hours_overdue', DATEDIFF(HOUR, LAST_BACKUP_AT, CURRENT_TIMESTAMP())
    )) INTO v_overdue_policies
    FROM BACKUP_POLICIES
    WHERE IS_ACTIVE = TRUE
      AND (
          (BACKUP_FREQUENCY = 'HOURLY' AND LAST_BACKUP_AT < DATEADD(HOUR, -2, CURRENT_TIMESTAMP()))
          OR (BACKUP_FREQUENCY = 'DAILY' AND LAST_BACKUP_AT < DATEADD(DAY, -2, CURRENT_TIMESTAMP()))
          OR (BACKUP_FREQUENCY = 'WEEKLY' AND LAST_BACKUP_AT < DATEADD(DAY, -8, CURRENT_TIMESTAMP()))
      );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_COMPLIANCE',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall', OBJECT_CONSTRUCT(
            'score', v_compliance_score,
            'max_score', v_max_score,
            'percentage', v_compliance_score,
            'grade', CASE 
                WHEN v_compliance_score >= 90 THEN 'A'
                WHEN v_compliance_score >= 75 THEN 'B'
                WHEN v_compliance_score >= 60 THEN 'C'
                WHEN v_compliance_score >= 40 THEN 'D'
                ELSE 'F'
            END,
            'status', CASE 
                WHEN v_compliance_score >= 80 THEN 'COMPLIANT'
                WHEN v_compliance_score >= 50 THEN 'PARTIALLY_COMPLIANT'
                ELSE 'NON_COMPLIANT'
            END
        ),
        'checks', v_checks,
        'databases_without_backup', COALESCE(v_databases_without_backup, ARRAY_CONSTRUCT()),
        'overdue_policies', COALESCE(v_overdue_policies, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 5: BACKUP HEALTH CHECK
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Health Check
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_HEALTH_CHECK()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_health_status VARCHAR := 'HEALTHY';
    v_issues VARIANT := ARRAY_CONSTRUCT();
    v_warnings VARIANT := ARRAY_CONSTRUCT();
    v_metrics VARIANT;
BEGIN
    -- Check for failed jobs in last 24 hours
    FOR job_rec IN (
        SELECT * FROM BACKUP_JOBS 
        WHERE STATUS = 'FAILED' AND STARTED_AT > DATEADD(HOUR, -24, CURRENT_TIMESTAMP())
    ) LOOP
        v_health_status := 'DEGRADED';
        v_issues := ARRAY_APPEND(v_issues, OBJECT_CONSTRUCT(
            'type', 'FAILED_JOB',
            'job_id', job_rec.JOB_ID,
            'error', job_rec.ERROR_MESSAGE,
            'timestamp', job_rec.STARTED_AT
        ));
    END LOOP;
    
    -- Check for overdue policies
    FOR policy_rec IN (
        SELECT POLICY_NAME, BACKUP_FREQUENCY, LAST_BACKUP_AT FROM BACKUP_POLICIES
        WHERE IS_ACTIVE = TRUE
          AND (
              (BACKUP_FREQUENCY = 'HOURLY' AND LAST_BACKUP_AT < DATEADD(HOUR, -2, CURRENT_TIMESTAMP()))
              OR (BACKUP_FREQUENCY = 'DAILY' AND LAST_BACKUP_AT < DATEADD(DAY, -2, CURRENT_TIMESTAMP()))
          )
    ) LOOP
        v_health_status := CASE WHEN v_health_status = 'HEALTHY' THEN 'WARNING' ELSE v_health_status END;
        v_warnings := ARRAY_APPEND(v_warnings, OBJECT_CONSTRUCT(
            'type', 'OVERDUE_POLICY',
            'policy_name', policy_rec.POLICY_NAME,
            'frequency', policy_rec.BACKUP_FREQUENCY,
            'last_backup', policy_rec.LAST_BACKUP_AT
        ));
    END LOOP;
    
    -- Check for expiring backups
    LET v_expiring_count INTEGER := 0;
    SELECT COUNT(*) INTO v_expiring_count
    FROM BACKUP_CATALOG
    WHERE STATUS = 'ACTIVE' 
      AND EXPIRES_AT BETWEEN CURRENT_TIMESTAMP() AND DATEADD(DAY, 3, CURRENT_TIMESTAMP());
    
    IF (v_expiring_count > 0) THEN
        v_warnings := ARRAY_APPEND(v_warnings, OBJECT_CONSTRUCT(
            'type', 'EXPIRING_BACKUPS',
            'count', v_expiring_count,
            'message', v_expiring_count || ' backups expiring in next 3 days'
        ));
    END IF;
    
    -- Get key metrics
    LET v_active_backups INTEGER := (SELECT COUNT_IF(STATUS = 'ACTIVE') FROM BACKUP_CATALOG);
    LET v_active_policies INTEGER := (SELECT COUNT(*) FROM BACKUP_POLICIES WHERE IS_ACTIVE = TRUE);
    LET v_jobs_24h INTEGER := (SELECT COUNT(*) FROM BACKUP_JOBS WHERE STARTED_AT > DATEADD(HOUR, -24, CURRENT_TIMESTAMP()));
    LET v_restores_7d INTEGER := (SELECT COUNT(*) FROM BACKUP_RESTORE_HISTORY WHERE STARTED_AT > DATEADD(DAY, -7, CURRENT_TIMESTAMP()));
    
    v_metrics := OBJECT_CONSTRUCT(
        'active_backups', v_active_backups,
        'active_policies', v_active_policies,
        'jobs_last_24h', v_jobs_24h,
        'restores_last_7d', v_restores_7d
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_HEALTH_CHECK',
        'generated_at', CURRENT_TIMESTAMP(),
        'health_status', v_health_status,
        'issues', v_issues,
        'warnings', v_warnings,
        'metrics', v_metrics,
        'recommendation', CASE v_health_status
            WHEN 'HEALTHY' THEN 'All backup systems operating normally'
            WHEN 'WARNING' THEN 'Review warnings and take action as needed'
            ELSE 'Immediate attention required - review issues'
        END
    );
END;
$$;

-- #############################################################################
-- SECTION 6: BACKUP TRENDS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Trends Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_TRENDS_DASHBOARD(
    P_DAYS INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_daily_backups VARIANT;
    v_daily_restores VARIANT;
    v_by_day_of_week VARIANT;
    v_growth_trend VARIANT;
BEGIN
    -- Daily backup counts
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', BACKUP_DATE,
        'count', CNT,
        'total_size_gb', SIZE_GB
    )) WITHIN GROUP (ORDER BY BACKUP_DATE) INTO v_daily_backups
    FROM (
        SELECT 
            TO_DATE(BACKUP_TIMESTAMP) AS BACKUP_DATE,
            COUNT(*) AS CNT,
            ROUND(SUM(COALESCE(SIZE_BYTES, 0)) / 1024 / 1024 / 1024, 2) AS SIZE_GB
        FROM BACKUP_CATALOG
        WHERE BACKUP_TIMESTAMP > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
        GROUP BY BACKUP_DATE
    );
    
    -- Daily restore counts
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', RESTORE_DATE,
        'count', CNT,
        'success_count', SUCCESS_CNT
    )) WITHIN GROUP (ORDER BY RESTORE_DATE) INTO v_daily_restores
    FROM (
        SELECT 
            TO_DATE(STARTED_AT) AS RESTORE_DATE,
            COUNT(*) AS CNT,
            COUNT_IF(STATUS = 'SUCCESS') AS SUCCESS_CNT
        FROM BACKUP_RESTORE_HISTORY
        WHERE STARTED_AT > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
        GROUP BY RESTORE_DATE
    );
    
    -- Backups by day of week
    SELECT OBJECT_AGG(DOW, CNT) INTO v_by_day_of_week
    FROM (
        SELECT DAYNAME(BACKUP_TIMESTAMP) AS DOW, COUNT(*) AS CNT
        FROM BACKUP_CATALOG
        WHERE BACKUP_TIMESTAMP > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
        GROUP BY DOW
    );
    
    -- Growth trend
    LET v_backups_first_half INTEGER := (SELECT COUNT(*) FROM BACKUP_CATALOG WHERE BACKUP_TIMESTAMP BETWEEN DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP()) AND DATEADD(DAY, -P_DAYS/2, CURRENT_TIMESTAMP()));
    LET v_backups_second_half INTEGER := (SELECT COUNT(*) FROM BACKUP_CATALOG WHERE BACKUP_TIMESTAMP > DATEADD(DAY, -P_DAYS/2, CURRENT_TIMESTAMP()));
    LET v_total_period_backups INTEGER := (SELECT COUNT(*) FROM BACKUP_CATALOG WHERE BACKUP_TIMESTAMP > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP()));
    
    v_growth_trend := OBJECT_CONSTRUCT(
        'backups_first_half', v_backups_first_half,
        'backups_second_half', v_backups_second_half,
        'total_period_backups', v_total_period_backups
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_TRENDS',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS,
        'daily_backups', COALESCE(v_daily_backups, ARRAY_CONSTRUCT()),
        'daily_restores', COALESCE(v_daily_restores, ARRAY_CONSTRUCT()),
        'by_day_of_week', COALESCE(v_by_day_of_week, OBJECT_CONSTRUCT()),
        'growth_trend', v_growth_trend
    );
END;
$$;

-- #############################################################################
-- SECTION 7: UNIFIED BACKUP MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Unified Backup Monitoring Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_status VARIANT;
    v_health VARIANT;
    v_compliance VARIANT;
    v_storage VARIANT;
    v_overall_health VARCHAR;
    v_alerts ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Gather dashboards
    CALL ADMIN.BACKUP.RBAC_BACKUP_STATUS_DASHBOARD() INTO v_status;
    CALL ADMIN.BACKUP.RBAC_BACKUP_HEALTH_CHECK() INTO v_health;
    CALL ADMIN.BACKUP.RBAC_BACKUP_COMPLIANCE_REPORT() INTO v_compliance;
    CALL ADMIN.BACKUP.RBAC_BACKUP_STORAGE_DASHBOARD() INTO v_storage;
    
    -- Determine overall health
    IF (v_health:health_status = 'DEGRADED') THEN
        v_overall_health := 'CRITICAL';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'CRITICAL',
            'message', 'Backup system has failures - immediate attention required',
            'source', 'HEALTH_CHECK'
        ));
    ELSEIF (v_compliance:overall:status = 'NON_COMPLIANT') THEN
        v_overall_health := 'WARNING';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', 'Backup compliance score below threshold',
            'source', 'COMPLIANCE'
        ));
    ELSEIF (v_health:health_status = 'WARNING') THEN
        v_overall_health := 'ATTENTION';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', 'Some backup policies are overdue',
            'source', 'HEALTH_CHECK'
        ));
    ELSE
        v_overall_health := 'HEALTHY';
    END IF;
    
    -- Add expiring backup alert
    IF (v_status:summary:expiring_in_7_days > 0) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', v_status:summary:expiring_in_7_days || ' backups expiring in 7 days',
            'source', 'STATUS'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'BACKUP_MONITORING_UNIFIED',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall_health', v_overall_health,
        'alerts', v_alerts,
        'quick_stats', OBJECT_CONSTRUCT(
            'active_backups', v_status:summary:active_backups,
            'expiring_soon', v_status:summary:expiring_in_7_days,
            'compliance_score', v_compliance:overall:percentage,
            'compliance_grade', v_compliance:overall:grade,
            'storage_gb', v_storage:summary:total_size_gb,
            'health_status', v_health:health_status
        ),
        'status', v_status,
        'health', v_health,
        'compliance', v_compliance,
        'storage', v_storage
    );
END;
$$;

-- #############################################################################
-- SECTION 8: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STATUS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STORAGE_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_TIME_TRAVEL_COVERAGE_DASHBOARD(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_COMPLIANCE_REPORT() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_HEALTH_CHECK() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_TRENDS_DASHBOARD(INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;

-- DBAdmins can view dashboards
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STATUS_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_STORAGE_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_TIME_TRAVEL_COVERAGE_DASHBOARD(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_HEALTH_CHECK() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_BACKUP_MONITORING_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
