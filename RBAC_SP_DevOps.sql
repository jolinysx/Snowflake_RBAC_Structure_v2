/*******************************************************************************
 * RBAC STORED PROCEDURE: DevOps & CI/CD Configuration
 * 
 * Purpose: Procedures for implementing CI/CD pipelines with Snowflake
 *          Supports Azure DevOps, GitHub Actions, GitLab, and other platforms
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          DEVOPS
 *   Object Type:     TABLES (3), PROCEDURES (~15)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_DEVOPS, SRS_SECURITY_ADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and DEVOPS schema must exist
 *     - ADMIN.RBAC procedures must be deployed first
 *     - SRS_SYSTEM_ADMIN, SRS_DEVOPS roles must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ARCHITECTURE OVERVIEW
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                         CI/CD PIPELINE FLOW                             │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
 *   │  │ Azure DevOps │    │GitHub Actions│    │   GitLab     │              │
 *   │  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘              │
 *   │         │                   │                   │                      │
 *   │         └───────────────────┼───────────────────┘                      │
 *   │                             ▼                                          │
 *   │              ┌──────────────────────────┐                              │
 *   │              │  SNOWFLAKE SERVICE ACCT  │                              │
 *   │              │  SRW_*_DEPLOYER role     │                              │
 *   │              └────────────┬─────────────┘                              │
 *   │                           │                                            │
 *   │         ┌─────────────────┼─────────────────┐                          │
 *   │         ▼                 ▼                 ▼                          │
 *   │    ┌─────────┐       ┌─────────┐       ┌─────────┐                     │
 *   │    │   DEV   │  ───► │   TST   │  ───► │   PRD   │                     │
 *   │    └─────────┘       └─────────┘       └─────────┘                     │
 *   │                                                                         │
 *   │    Deploy ──► Log ──► Verify ──► Promote ──► Monitor                   │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * KEY CONCEPTS:
 *   - DEPLOYER roles: Special SRW_* roles for CI/CD pipelines
 *   - Deployment tracking: All deployments logged for audit
 *   - Environment promotion: Controlled flow DEV → TST → UAT → PRD
 *   - Git integration: Native Snowflake Git repository support
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA DEVOPS;

-- #############################################################################
-- SECTION 1: DEPLOYMENT TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_DEPLOYMENTS (
    DEPLOYMENT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    DEPLOYMENT_TYPE VARCHAR(50) NOT NULL,
    SOURCE_ENVIRONMENT VARCHAR(10),
    TARGET_ENVIRONMENT VARCHAR(10) NOT NULL,
    DATABASE_NAME VARCHAR(255),
    SCHEMA_NAME VARCHAR(255),
    OBJECT_TYPE VARCHAR(50),
    OBJECT_NAME VARCHAR(255),
    PIPELINE_NAME VARCHAR(255),
    PIPELINE_RUN_ID VARCHAR(255),
    COMMIT_SHA VARCHAR(100),
    BRANCH_NAME VARCHAR(255),
    DEPLOYED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    STATUS VARCHAR(20) DEFAULT 'PENDING',
    STARTED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    COMPLETED_AT TIMESTAMP_NTZ,
    ROLLBACK_ID VARCHAR(36),
    METADATA VARIANT,
    ERROR_MESSAGE TEXT
);

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_DEPLOYMENT_OBJECTS (
    ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    DEPLOYMENT_ID VARCHAR(36) NOT NULL,
    OBJECT_TYPE VARCHAR(50) NOT NULL,
    OBJECT_NAME VARCHAR(255) NOT NULL,
    OPERATION VARCHAR(20) NOT NULL,
    PREVIOUS_DEFINITION TEXT,
    NEW_DEFINITION TEXT,
    STATUS VARCHAR(20) DEFAULT 'PENDING',
    ERROR_MESSAGE TEXT,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (DEPLOYMENT_ID) REFERENCES DEVOPS_DEPLOYMENTS(DEPLOYMENT_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.DEVOPS.DEVOPS_GIT_REPOSITORIES (
    REPO_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    REPO_NAME VARCHAR(255) NOT NULL UNIQUE,
    INTEGRATION_NAME VARCHAR(255) NOT NULL,
    ORIGIN_URL VARCHAR(1000),
    DEFAULT_BRANCH VARCHAR(100) DEFAULT 'main',
    ENVIRONMENTS ARRAY,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    LAST_SYNC_AT TIMESTAMP_NTZ
);

-- #############################################################################
-- SECTION 2: PIPELINE SERVICE ACCOUNT SETUP
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create CI/CD Pipeline Service Account
 * 
 * Purpose: Creates a service account specifically for CI/CD deployments
 *          Uses existing RBAC procedures with deployment-specific configuration
 * 
 * Parameters:
 *   P_PIPELINE_NAME   - Name of the pipeline (e.g., 'AZURE_DEVOPS', 'GITHUB_ACTIONS')
 *   P_DOMAIN          - Domain this pipeline deploys to
 *   P_RSA_PUBLIC_KEY  - RSA public key for authentication
 *   P_ENVIRONMENTS    - Array of environments this pipeline can deploy to
 *   P_CAPABILITY      - Capability level (default: DEVELOPER for write access)
 *   P_COMMENT         - Description
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(
    P_PIPELINE_NAME VARCHAR,
    P_DOMAIN VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENTS ARRAY DEFAULT NULL,
    P_CAPABILITY VARCHAR DEFAULT 'DEVELOPER',
    P_COMMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_account_name VARCHAR;
    v_environments ARRAY;
    v_result VARIANT;
    v_grants ARRAY := ARRAY_CONSTRUCT();
    v_first_env VARCHAR;
BEGIN
    v_environments := COALESCE(P_ENVIRONMENTS, ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PRD'));
    v_service_account_name := UPPER(P_PIPELINE_NAME) || '_' || UPPER(P_DOMAIN) || '_DEPLOYER';
    v_first_env := v_environments[0]::VARCHAR;
    
    -- Create service role for the first environment
    CALL ADMIN.RBAC.RBAC_CREATE_SERVICE_ROLE(
        v_first_env,
        P_DOMAIN,
        P_CAPABILITY,
        COALESCE(P_COMMENT, 'CI/CD deployer for ' || P_DOMAIN)
    );
    
    -- Create the service account
    CALL ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT(
        v_service_account_name,
        P_RSA_PUBLIC_KEY,
        v_first_env,
        P_DOMAIN,
        P_CAPABILITY,
        v_first_env || '_WH',
        COALESCE(P_COMMENT, 'CI/CD pipeline service account for ' || P_PIPELINE_NAME),
        NULL
    ) INTO v_result;
    
    -- Grant access to additional environments
    FOR i IN 1 TO ARRAY_SIZE(v_environments) - 1 DO
        LET v_env VARCHAR := v_environments[i]::VARCHAR;
        
        BEGIN
            CALL ADMIN.RBAC.RBAC_GRANT_SERVICE_ACCOUNT(
                v_service_account_name,
                v_env,
                P_DOMAIN,
                P_CAPABILITY,
                FALSE
            );
            v_grants := ARRAY_APPEND(v_grants, OBJECT_CONSTRUCT(
                'environment', v_env,
                'status', 'GRANTED'
            ));
        EXCEPTION
            WHEN OTHER THEN
                v_grants := ARRAY_APPEND(v_grants, OBJECT_CONSTRUCT(
                    'environment', v_env,
                    'status', 'FAILED',
                    'error', SQLERRM
                ));
        END;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'service_account', v_service_account_name,
        'pipeline', P_PIPELINE_NAME,
        'domain', P_DOMAIN,
        'capability', P_CAPABILITY,
        'environments', v_environments,
        'additional_grants', v_grants,
        'connection_details', OBJECT_CONSTRUCT(
            'account', CURRENT_ACCOUNT(),
            'user', v_service_account_name,
            'authenticator', 'SNOWFLAKE_JWT',
            'role', 'SRW_' || v_first_env || '_' || P_DOMAIN || '_' || P_CAPABILITY,
            'warehouse', v_first_env || '_WH'
        ),
        'next_steps', ARRAY_CONSTRUCT(
            '1. Store RSA private key securely in your CI/CD platform',
            '2. Configure connection in pipeline (see connection_details)',
            '3. Test connection: CALL DEVOPS_TEST_PIPELINE_CONNECTION();'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Azure DevOps Pipeline
 * 
 * Purpose: Complete setup for Azure DevOps integration
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_AZURE_DEVOPS(
    P_PROJECT_NAME VARCHAR,
    P_DOMAIN VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENTS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    CALL ADMIN.DEVOPS.DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(
        'AZURE_DEVOPS_' || P_PROJECT_NAME,
        P_DOMAIN,
        P_RSA_PUBLIC_KEY,
        P_ENVIRONMENTS,
        'DEVELOPER',
        'Azure DevOps pipeline for ' || P_PROJECT_NAME
    ) INTO v_result;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_result:status,
        'platform', 'AZURE_DEVOPS',
        'project', P_PROJECT_NAME,
        'service_account', v_result:service_account,
        'azure_devops_config', OBJECT_CONSTRUCT(
            'service_connection_type', 'Snowflake',
            'authentication', 'Key Pair',
            'account_identifier', CURRENT_ACCOUNT() || '.snowflakecomputing.com',
            'username', v_result:service_account,
            'private_key', '$(SNOWFLAKE_PRIVATE_KEY)',
            'warehouse', v_result:connection_details:warehouse,
            'role', v_result:connection_details:role
        ),
        'pipeline_yaml_example', '
# azure-pipelines.yml
variables:
  SNOWFLAKE_ACCOUNT: ' || CURRENT_ACCOUNT() || '
  SNOWFLAKE_USER: ' || v_result:service_account::VARCHAR || '
  SNOWFLAKE_ROLE: ' || v_result:connection_details:role::VARCHAR || '
  SNOWFLAKE_WAREHOUSE: ' || v_result:connection_details:warehouse::VARCHAR || '

stages:
- stage: Deploy_DEV
  jobs:
  - job: DeploySnowflake
    steps:
    - task: SnowflakeCLI@1
      inputs:
        account: $(SNOWFLAKE_ACCOUNT)
        username: $(SNOWFLAKE_USER)
        privateKey: $(SNOWFLAKE_PRIVATE_KEY)
        role: $(SNOWFLAKE_ROLE)
        warehouse: $(SNOWFLAKE_WAREHOUSE)
        command: sql -f deploy.sql
'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup GitHub Actions Pipeline
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GITHUB_ACTIONS(
    P_REPO_NAME VARCHAR,
    P_DOMAIN VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENTS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    CALL ADMIN.DEVOPS.DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(
        'GITHUB_' || REPLACE(P_REPO_NAME, '-', '_'),
        P_DOMAIN,
        P_RSA_PUBLIC_KEY,
        P_ENVIRONMENTS,
        'DEVELOPER',
        'GitHub Actions pipeline for ' || P_REPO_NAME
    ) INTO v_result;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_result:status,
        'platform', 'GITHUB_ACTIONS',
        'repository', P_REPO_NAME,
        'service_account', v_result:service_account,
        'github_secrets', OBJECT_CONSTRUCT(
            'SNOWFLAKE_ACCOUNT', CURRENT_ACCOUNT(),
            'SNOWFLAKE_USER', v_result:service_account,
            'SNOWFLAKE_PRIVATE_KEY', '<your-private-key-base64>',
            'SNOWFLAKE_ROLE', v_result:connection_details:role,
            'SNOWFLAKE_WAREHOUSE', v_result:connection_details:warehouse
        ),
        'workflow_yaml_example', '
# .github/workflows/deploy.yml
name: Deploy to Snowflake

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  SNOWFLAKE_ACCOUNT: ${{ secrets.SNOWFLAKE_ACCOUNT }}
  SNOWFLAKE_USER: ${{ secrets.SNOWFLAKE_USER }}
  SNOWFLAKE_ROLE: ${{ secrets.SNOWFLAKE_ROLE }}
  SNOWFLAKE_WAREHOUSE: ${{ secrets.SNOWFLAKE_WAREHOUSE }}

jobs:
  deploy-dev:
    runs-on: ubuntu-latest
    environment: development
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Snowflake CLI
        uses: Snowflake-Labs/snowflake-cli-action@v1
        with:
          cli-version: latest
          default-config-file-path: config.toml
      
      - name: Deploy to Snowflake
        env:
          SNOWFLAKE_PRIVATE_KEY: ${{ secrets.SNOWFLAKE_PRIVATE_KEY }}
        run: |
          snow sql -f deploy.sql
'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup GitLab CI/CD Pipeline
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GITLAB(
    P_PROJECT_NAME VARCHAR,
    P_DOMAIN VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENTS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    CALL ADMIN.DEVOPS.DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(
        'GITLAB_' || REPLACE(P_PROJECT_NAME, '-', '_'),
        P_DOMAIN,
        P_RSA_PUBLIC_KEY,
        P_ENVIRONMENTS,
        'DEVELOPER',
        'GitLab CI/CD pipeline for ' || P_PROJECT_NAME
    ) INTO v_result;
    
    RETURN OBJECT_CONSTRUCT(
        'status', v_result:status,
        'platform', 'GITLAB',
        'project', P_PROJECT_NAME,
        'service_account', v_result:service_account,
        'gitlab_variables', OBJECT_CONSTRUCT(
            'SNOWFLAKE_ACCOUNT', CURRENT_ACCOUNT(),
            'SNOWFLAKE_USER', v_result:service_account,
            'SNOWFLAKE_PRIVATE_KEY', '<your-private-key>',
            'SNOWFLAKE_ROLE', v_result:connection_details:role,
            'SNOWFLAKE_WAREHOUSE', v_result:connection_details:warehouse
        ),
        'gitlab_ci_example', '
# .gitlab-ci.yml
stages:
  - deploy-dev
  - deploy-tst
  - deploy-prd

variables:
  SNOWFLAKE_ACCOUNT: $SNOWFLAKE_ACCOUNT
  SNOWFLAKE_USER: $SNOWFLAKE_USER
  SNOWFLAKE_ROLE: $SNOWFLAKE_ROLE
  SNOWFLAKE_WAREHOUSE: $SNOWFLAKE_WAREHOUSE

deploy-dev:
  stage: deploy-dev
  image: snowflakedb/snowflake-cli:latest
  script:
    - echo "$SNOWFLAKE_PRIVATE_KEY" > /tmp/rsa_key.p8
    - snow sql -f deploy.sql
  only:
    - develop

deploy-prd:
  stage: deploy-prd
  image: snowflakedb/snowflake-cli:latest
  script:
    - snow sql -f deploy.sql
  only:
    - main
  when: manual
'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: SNOWFLAKE NATIVE GIT INTEGRATION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Git Repository Integration
 * 
 * Purpose: Configures Snowflake native Git repository integration
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GIT_REPOSITORY(
    P_REPO_NAME VARCHAR,
    P_GIT_URL VARCHAR,
    P_GIT_PROVIDER VARCHAR,
    P_SECRET_NAME VARCHAR,
    P_API_INTEGRATION_NAME VARCHAR DEFAULT NULL,
    P_DEFAULT_BRANCH VARCHAR DEFAULT 'main'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_api_integration VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    v_api_integration := COALESCE(P_API_INTEGRATION_NAME, 'GIT_API_' || UPPER(P_GIT_PROVIDER));
    
    -- Create API integration for Git provider (if not exists)
    IF (P_GIT_PROVIDER = 'GITHUB') THEN
        v_sql := 'CREATE API INTEGRATION IF NOT EXISTS ' || v_api_integration || '
            API_PROVIDER = GIT_HTTPS_API
            API_ALLOWED_PREFIXES = (''https://github.com'')
            ALLOWED_AUTHENTICATION_SECRETS = (' || P_SECRET_NAME || ')
            ENABLED = TRUE';
    ELSEIF (P_GIT_PROVIDER = 'GITLAB') THEN
        v_sql := 'CREATE API INTEGRATION IF NOT EXISTS ' || v_api_integration || '
            API_PROVIDER = GIT_HTTPS_API
            API_ALLOWED_PREFIXES = (''https://gitlab.com'')
            ALLOWED_AUTHENTICATION_SECRETS = (' || P_SECRET_NAME || ')
            ENABLED = TRUE';
    ELSEIF (P_GIT_PROVIDER = 'AZURE_DEVOPS') THEN
        v_sql := 'CREATE API INTEGRATION IF NOT EXISTS ' || v_api_integration || '
            API_PROVIDER = GIT_HTTPS_API
            API_ALLOWED_PREFIXES = (''https://dev.azure.com'')
            ALLOWED_AUTHENTICATION_SECRETS = (' || P_SECRET_NAME || ')
            ENABLED = TRUE';
    ELSE
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Unsupported Git provider: ' || P_GIT_PROVIDER);
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_API_INTEGRATION', 'name', v_api_integration));
    
    -- Create Git repository
    v_sql := 'CREATE OR REPLACE GIT REPOSITORY ' || P_REPO_NAME || '
        API_INTEGRATION = ' || v_api_integration || '
        GIT_CREDENTIALS = ' || P_SECRET_NAME || '
        ORIGIN = ''' || P_GIT_URL || '''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_GIT_REPOSITORY', 'name', P_REPO_NAME));
    
    -- Fetch the repository
    v_sql := 'ALTER GIT REPOSITORY ' || P_REPO_NAME || ' FETCH';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'FETCH_REPOSITORY'));
    
    -- Log the repository
    INSERT INTO DEVOPS_GIT_REPOSITORIES (REPO_NAME, INTEGRATION_NAME, ORIGIN_URL, DEFAULT_BRANCH)
    VALUES (P_REPO_NAME, v_api_integration, P_GIT_URL, P_DEFAULT_BRANCH);
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'repository_name', P_REPO_NAME,
        'git_url', P_GIT_URL,
        'provider', P_GIT_PROVIDER,
        'api_integration', v_api_integration,
        'default_branch', P_DEFAULT_BRANCH,
        'actions', v_actions,
        'usage', ARRAY_CONSTRUCT(
            'List branches: SHOW GIT BRANCHES IN ' || P_REPO_NAME,
            'List files: LS @' || P_REPO_NAME || '/branches/' || P_DEFAULT_BRANCH,
            'Execute SQL: EXECUTE IMMEDIATE FROM @' || P_REPO_NAME || '/branches/' || P_DEFAULT_BRANCH || '/deploy.sql',
            'Fetch updates: ALTER GIT REPOSITORY ' || P_REPO_NAME || ' FETCH'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Git Credentials Secret
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_CREATE_GIT_SECRET(
    P_SECRET_NAME VARCHAR,
    P_GIT_PROVIDER VARCHAR,
    P_USERNAME VARCHAR,
    P_TOKEN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    v_sql := 'CREATE OR REPLACE SECRET ' || P_SECRET_NAME || '
        TYPE = PASSWORD
        USERNAME = ''' || P_USERNAME || '''
        PASSWORD = ''' || P_TOKEN || '''
        COMMENT = ''Git credentials for ' || P_GIT_PROVIDER || '''';
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'secret_name', P_SECRET_NAME,
        'git_provider', P_GIT_PROVIDER,
        'username', P_USERNAME,
        'note', 'Secret created. Use this with DEVOPS_SETUP_GIT_REPOSITORY'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: DEPLOYMENT MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Start Deployment
 * 
 * Purpose: Initiates a tracked deployment
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
    P_TARGET_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR DEFAULT NULL,
    P_DEPLOYMENT_TYPE VARCHAR DEFAULT 'SCHEMA',
    P_PIPELINE_NAME VARCHAR DEFAULT NULL,
    P_PIPELINE_RUN_ID VARCHAR DEFAULT NULL,
    P_COMMIT_SHA VARCHAR DEFAULT NULL,
    P_BRANCH_NAME VARCHAR DEFAULT NULL,
    P_METADATA VARIANT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_deployment_id VARCHAR;
BEGIN
    v_deployment_id := UUID_STRING();
    
    INSERT INTO DEVOPS_DEPLOYMENTS (
        DEPLOYMENT_ID, DEPLOYMENT_TYPE, TARGET_ENVIRONMENT, DATABASE_NAME,
        SCHEMA_NAME, PIPELINE_NAME, PIPELINE_RUN_ID, COMMIT_SHA, BRANCH_NAME,
        STATUS, METADATA
    ) VALUES (
        v_deployment_id, P_DEPLOYMENT_TYPE, P_TARGET_ENVIRONMENT, P_DATABASE_NAME,
        P_SCHEMA_NAME, P_PIPELINE_NAME, P_PIPELINE_RUN_ID, P_COMMIT_SHA, P_BRANCH_NAME,
        'IN_PROGRESS', P_METADATA
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'deployment_id', v_deployment_id,
        'target_environment', P_TARGET_ENVIRONMENT,
        'database', P_DATABASE_NAME,
        'schema', P_SCHEMA_NAME,
        'message', 'Deployment started. Use DEVOPS_COMPLETE_DEPLOYMENT when finished.'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Deployment Object
 * 
 * Purpose: Logs individual objects being deployed
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_LOG_DEPLOYMENT_OBJECT(
    P_DEPLOYMENT_ID VARCHAR,
    P_OBJECT_TYPE VARCHAR,
    P_OBJECT_NAME VARCHAR,
    P_OPERATION VARCHAR,
    P_NEW_DEFINITION TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    INSERT INTO DEVOPS_DEPLOYMENT_OBJECTS (
        DEPLOYMENT_ID, OBJECT_TYPE, OBJECT_NAME, OPERATION, NEW_DEFINITION
    ) VALUES (
        P_DEPLOYMENT_ID, P_OBJECT_TYPE, P_OBJECT_NAME, P_OPERATION, P_NEW_DEFINITION
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'deployment_id', P_DEPLOYMENT_ID,
        'object', P_OBJECT_NAME,
        'operation', P_OPERATION
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Complete Deployment
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
    P_DEPLOYMENT_ID VARCHAR,
    P_STATUS VARCHAR DEFAULT 'SUCCESS',
    P_ERROR_MESSAGE TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    UPDATE DEVOPS_DEPLOYMENTS
    SET STATUS = P_STATUS,
        COMPLETED_AT = CURRENT_TIMESTAMP(),
        ERROR_MESSAGE = P_ERROR_MESSAGE
    WHERE DEPLOYMENT_ID = P_DEPLOYMENT_ID;
    
    UPDATE DEVOPS_DEPLOYMENT_OBJECTS
    SET STATUS = P_STATUS
    WHERE DEPLOYMENT_ID = P_DEPLOYMENT_ID;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'deployment_id', P_DEPLOYMENT_ID,
        'deployment_status', P_STATUS,
        'completed_at', CURRENT_TIMESTAMP()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Execute SQL from Git Repository
 * 
 * Purpose: Executes SQL file from a Git repository with deployment tracking
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_DEPLOY_FROM_GIT(
    P_REPOSITORY VARCHAR,
    P_BRANCH VARCHAR,
    P_FILE_PATH VARCHAR,
    P_TARGET_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_deployment_id VARCHAR;
    v_result VARIANT;
    v_file_location VARCHAR;
BEGIN
    -- Start deployment
    CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
        P_TARGET_ENVIRONMENT,
        P_DATABASE_NAME,
        P_SCHEMA_NAME,
        'GIT_DEPLOY',
        P_REPOSITORY,
        NULL,
        NULL,
        P_BRANCH,
        OBJECT_CONSTRUCT('file_path', P_FILE_PATH)
    ) INTO v_result;
    
    v_deployment_id := v_result:deployment_id::VARCHAR;
    
    -- Build file location
    v_file_location := '@' || P_REPOSITORY || '/branches/' || P_BRANCH || '/' || P_FILE_PATH;
    
    -- Execute the SQL file
    BEGIN
        -- Use dynamic SQL to execute from the file location
        LET v_exec_sql VARCHAR := 'EXECUTE IMMEDIATE FROM ' || v_file_location;
        EXECUTE IMMEDIATE v_exec_sql;
        
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(v_deployment_id, 'SUCCESS', NULL);
        
        RETURN OBJECT_CONSTRUCT(
            'status', 'SUCCESS',
            'deployment_id', v_deployment_id,
            'repository', P_REPOSITORY,
            'branch', P_BRANCH,
            'file', P_FILE_PATH,
            'target', P_TARGET_ENVIRONMENT || '.' || P_DATABASE_NAME || COALESCE('.' || P_SCHEMA_NAME, '')
        );
    EXCEPTION
        WHEN OTHER THEN
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(v_deployment_id, 'FAILED', SQLERRM);
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'deployment_id', v_deployment_id,
                'message', SQLERRM
            );
    END;

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: ENVIRONMENT PROMOTION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Promote Schema Between Environments
 * 
 * Purpose: Promotes schema objects from one environment to another
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_PROMOTE_SCHEMA(
    P_SOURCE_ENVIRONMENT VARCHAR,
    P_TARGET_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_OBJECT_TYPES ARRAY DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_source_db VARCHAR;
    v_target_db VARCHAR;
    v_object_types ARRAY;
    v_deployment_id VARCHAR;
    v_objects_to_promote ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
BEGIN
    -- Validate promotion path
    IF (NOT (
        (P_SOURCE_ENVIRONMENT = 'DEV' AND P_TARGET_ENVIRONMENT = 'TST') OR
        (P_SOURCE_ENVIRONMENT = 'TST' AND P_TARGET_ENVIRONMENT = 'UAT') OR
        (P_SOURCE_ENVIRONMENT = 'UAT' AND P_TARGET_ENVIRONMENT = 'PPE') OR
        (P_SOURCE_ENVIRONMENT = 'PPE' AND P_TARGET_ENVIRONMENT = 'PRD') OR
        (P_SOURCE_ENVIRONMENT = 'DEV' AND P_TARGET_ENVIRONMENT = 'UAT') OR
        (P_SOURCE_ENVIRONMENT = 'UAT' AND P_TARGET_ENVIRONMENT = 'PRD')
    )) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid promotion path. Valid: DEV→TST→UAT→PPE→PRD'
        );
    END IF;
    
    v_source_db := P_DATABASE_NAME || '_' || P_SOURCE_ENVIRONMENT;
    v_target_db := P_DATABASE_NAME || '_' || P_TARGET_ENVIRONMENT;
    v_object_types := COALESCE(P_OBJECT_TYPES, ARRAY_CONSTRUCT('TABLE', 'VIEW', 'PROCEDURE', 'FUNCTION', 'STREAM', 'TASK'));
    
    -- Start deployment tracking
    IF (NOT P_DRY_RUN) THEN
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
            P_TARGET_ENVIRONMENT,
            P_DATABASE_NAME,
            P_SCHEMA_NAME,
            'PROMOTION',
            'MANUAL_PROMOTION',
            NULL,
            NULL,
            NULL,
            OBJECT_CONSTRUCT('source_environment', P_SOURCE_ENVIRONMENT)
        );
        v_deployment_id := (SELECT DEPLOYMENT_ID FROM DEVOPS_DEPLOYMENTS ORDER BY STARTED_AT DESC LIMIT 1);
    END IF;
    
    -- Get objects from source schema
    FOR obj IN (
        SELECT OBJECT_TYPE, OBJECT_NAME 
        FROM INFORMATION_SCHEMA.OBJECT_PRIVILEGES
        WHERE OBJECT_CATALOG = :v_source_db
          AND OBJECT_SCHEMA = :P_SCHEMA_NAME
          AND OBJECT_TYPE IN (SELECT VALUE FROM TABLE(FLATTEN(:v_object_types)))
        GROUP BY OBJECT_TYPE, OBJECT_NAME
    ) DO
        v_objects_to_promote := ARRAY_APPEND(v_objects_to_promote, OBJECT_CONSTRUCT(
            'type', obj.OBJECT_TYPE,
            'name', obj.OBJECT_NAME,
            'source', v_source_db || '.' || P_SCHEMA_NAME || '.' || obj.OBJECT_NAME,
            'target', v_target_db || '.' || P_SCHEMA_NAME || '.' || obj.OBJECT_NAME
        ));
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'source', v_source_db || '.' || P_SCHEMA_NAME,
        'target', v_target_db || '.' || P_SCHEMA_NAME,
        'objects_count', ARRAY_SIZE(v_objects_to_promote),
        'objects', v_objects_to_promote,
        'deployment_id', v_deployment_id,
        'note', 'For actual promotion, use CLONE or re-run DDL from Git repository'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Schema for Promotion
 * 
 * Purpose: Clones entire schema from source to target environment
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_CLONE_SCHEMA(
    P_SOURCE_ENVIRONMENT VARCHAR,
    P_TARGET_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_INCLUDE_DATA BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_source_schema VARCHAR;
    v_target_schema VARCHAR;
    v_sql VARCHAR;
    v_deployment_id VARCHAR;
    v_result VARIANT;
BEGIN
    v_source_schema := P_DATABASE_NAME || '_' || P_SOURCE_ENVIRONMENT || '.' || P_SCHEMA_NAME;
    v_target_schema := P_DATABASE_NAME || '_' || P_TARGET_ENVIRONMENT || '.' || P_SCHEMA_NAME;
    
    -- Start deployment
    CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
        P_TARGET_ENVIRONMENT,
        P_DATABASE_NAME,
        P_SCHEMA_NAME,
        'CLONE',
        'SCHEMA_CLONE',
        NULL,
        NULL,
        NULL,
        OBJECT_CONSTRUCT(
            'source_environment', P_SOURCE_ENVIRONMENT,
            'include_data', P_INCLUDE_DATA
        )
    ) INTO v_result;
    v_deployment_id := v_result:deployment_id::VARCHAR;
    
    -- Clone the schema
    IF (P_INCLUDE_DATA) THEN
        v_sql := 'CREATE OR REPLACE SCHEMA ' || v_target_schema || ' CLONE ' || v_source_schema;
    ELSE
        v_sql := 'CREATE OR REPLACE SCHEMA ' || v_target_schema || ' CLONE ' || v_source_schema || ' COPY GRANTS';
    END IF;
    
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(v_deployment_id, 'SUCCESS', NULL);
        
        RETURN OBJECT_CONSTRUCT(
            'status', 'SUCCESS',
            'deployment_id', v_deployment_id,
            'source_schema', v_source_schema,
            'target_schema', v_target_schema,
            'include_data', P_INCLUDE_DATA,
            'message', 'Schema cloned successfully'
        );
    EXCEPTION
        WHEN OTHER THEN
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(v_deployment_id, 'FAILED', SQLERRM);
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'deployment_id', v_deployment_id,
                'message', SQLERRM
            );
    END;

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: ROLLBACK PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Rollback Deployment
 * 
 * Purpose: Rolls back a deployment using Time Travel or previous definitions
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_ROLLBACK_DEPLOYMENT(
    P_DEPLOYMENT_ID VARCHAR,
    P_ROLLBACK_TYPE VARCHAR DEFAULT 'TIME_TRAVEL',
    P_POINT_IN_TIME TIMESTAMP_NTZ DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_deployment VARIANT;
    v_rollback_id VARCHAR;
    v_target_time TIMESTAMP_NTZ;
BEGIN
    -- Get deployment details
    SELECT OBJECT_CONSTRUCT(*) INTO v_deployment
    FROM DEVOPS_DEPLOYMENTS
    WHERE DEPLOYMENT_ID = P_DEPLOYMENT_ID;
    
    IF (v_deployment IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Deployment not found');
    END IF;
    
    v_target_time := COALESCE(P_POINT_IN_TIME, v_deployment:STARTED_AT::TIMESTAMP_NTZ);
    v_rollback_id := UUID_STRING();
    
    -- Log rollback
    INSERT INTO DEVOPS_DEPLOYMENTS (
        DEPLOYMENT_ID, DEPLOYMENT_TYPE, TARGET_ENVIRONMENT, DATABASE_NAME,
        SCHEMA_NAME, STATUS, ROLLBACK_ID, METADATA
    ) VALUES (
        v_rollback_id,
        'ROLLBACK',
        v_deployment:TARGET_ENVIRONMENT::VARCHAR,
        v_deployment:DATABASE_NAME::VARCHAR,
        v_deployment:SCHEMA_NAME::VARCHAR,
        'IN_PROGRESS',
        P_DEPLOYMENT_ID,
        OBJECT_CONSTRUCT(
            'rollback_type', P_ROLLBACK_TYPE,
            'target_time', v_target_time,
            'original_deployment', P_DEPLOYMENT_ID
        )
    );
    
    -- Note: Actual rollback depends on object type and availability
    -- Time Travel example for tables would be:
    -- CREATE OR REPLACE TABLE ... CLONE ... AT(TIMESTAMP => v_target_time)
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'rollback_id', v_rollback_id,
        'original_deployment_id', P_DEPLOYMENT_ID,
        'rollback_type', P_ROLLBACK_TYPE,
        'target_time', v_target_time,
        'next_steps', ARRAY_CONSTRUCT(
            'For TABLE rollback: Use CLONE with AT(TIMESTAMP => ''' || v_target_time || ''')',
            'For SCHEMA rollback: Use UNDROP or CLONE from Time Travel',
            'For code objects: Re-deploy from previous Git commit'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 7: DEPLOYMENT MONITORING & AUDIT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Deployment History
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_GET_DEPLOYMENT_HISTORY(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_DATABASE_NAME VARCHAR DEFAULT NULL,
    P_DAYS_BACK INTEGER DEFAULT 30,
    P_STATUS VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    DEPLOYMENT_ID VARCHAR,
    DEPLOYMENT_TYPE VARCHAR,
    TARGET_ENVIRONMENT VARCHAR,
    DATABASE_NAME VARCHAR,
    SCHEMA_NAME VARCHAR,
    PIPELINE_NAME VARCHAR,
    STATUS VARCHAR,
    DEPLOYED_BY VARCHAR,
    STARTED_AT TIMESTAMP_NTZ,
    COMPLETED_AT TIMESTAMP_NTZ,
    DURATION_SECONDS NUMBER
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
            DEPLOYMENT_ID,
            DEPLOYMENT_TYPE,
            TARGET_ENVIRONMENT,
            DATABASE_NAME,
            SCHEMA_NAME,
            PIPELINE_NAME,
            STATUS,
            DEPLOYED_BY,
            STARTED_AT,
            COMPLETED_AT,
            TIMESTAMPDIFF(SECOND, STARTED_AT, COALESCE(COMPLETED_AT, CURRENT_TIMESTAMP())) AS DURATION_SECONDS
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_DATE())
          AND (P_ENVIRONMENT IS NULL OR TARGET_ENVIRONMENT = P_ENVIRONMENT)
          AND (P_DATABASE_NAME IS NULL OR DATABASE_NAME = P_DATABASE_NAME)
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
        ORDER BY STARTED_AT DESC
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Deployment Details
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_GET_DEPLOYMENT_DETAILS(
    P_DEPLOYMENT_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_deployment VARIANT;
    v_objects ARRAY;
BEGIN
    SELECT OBJECT_CONSTRUCT(*) INTO v_deployment
    FROM DEVOPS_DEPLOYMENTS
    WHERE DEPLOYMENT_ID = P_DEPLOYMENT_ID;
    
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'object_type', OBJECT_TYPE,
        'object_name', OBJECT_NAME,
        'operation', OPERATION,
        'status', STATUS,
        'error', ERROR_MESSAGE
    )) INTO v_objects
    FROM DEVOPS_DEPLOYMENT_OBJECTS
    WHERE DEPLOYMENT_ID = P_DEPLOYMENT_ID;
    
    RETURN OBJECT_CONSTRUCT(
        'deployment', v_deployment,
        'objects', COALESCE(v_objects, ARRAY_CONSTRUCT())
    );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate Deployment Report
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_GENERATE_DEPLOYMENT_REPORT(
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_start DATE;
    v_end DATE;
    v_summary VARIANT;
    v_by_environment VARIANT;
    v_by_status VARIANT;
    v_by_pipeline VARIANT;
BEGIN
    v_start := COALESCE(P_START_DATE, DATEADD(DAY, -30, CURRENT_DATE()));
    v_end := COALESCE(P_END_DATE, CURRENT_DATE());
    
    -- Summary
    SELECT OBJECT_CONSTRUCT(
        'total_deployments', COUNT(*),
        'successful', COUNT_IF(STATUS = 'SUCCESS'),
        'failed', COUNT_IF(STATUS = 'FAILED'),
        'in_progress', COUNT_IF(STATUS = 'IN_PROGRESS'),
        'success_rate', ROUND(COUNT_IF(STATUS = 'SUCCESS') * 100.0 / NULLIF(COUNT(*), 0), 2),
        'avg_duration_seconds', ROUND(AVG(TIMESTAMPDIFF(SECOND, STARTED_AT, COMPLETED_AT)), 2)
    ) INTO v_summary
    FROM DEVOPS_DEPLOYMENTS
    WHERE STARTED_AT::DATE BETWEEN v_start AND v_end;
    
    -- By environment
    SELECT OBJECT_AGG(TARGET_ENVIRONMENT, cnt) INTO v_by_environment
    FROM (
        SELECT TARGET_ENVIRONMENT, COUNT(*) AS cnt
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT::DATE BETWEEN v_start AND v_end
        GROUP BY TARGET_ENVIRONMENT
    );
    
    -- By status
    SELECT OBJECT_AGG(STATUS, cnt) INTO v_by_status
    FROM (
        SELECT STATUS, COUNT(*) AS cnt
        FROM DEVOPS_DEPLOYMENTS
        WHERE STARTED_AT::DATE BETWEEN v_start AND v_end
        GROUP BY STATUS
    );
    
    RETURN OBJECT_CONSTRUCT(
        'report_period', OBJECT_CONSTRUCT('start', v_start, 'end', v_end),
        'summary', v_summary,
        'by_environment', v_by_environment,
        'by_status', v_by_status
    );
END;
$$;

-- #############################################################################
-- SECTION 8: UTILITY PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Test Pipeline Connection
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_TEST_CONNECTION()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'connection', OBJECT_CONSTRUCT(
            'user', CURRENT_USER(),
            'role', CURRENT_ROLE(),
            'warehouse', CURRENT_WAREHOUSE(),
            'database', CURRENT_DATABASE(),
            'schema', CURRENT_SCHEMA(),
            'account', CURRENT_ACCOUNT(),
            'timestamp', CURRENT_TIMESTAMP()
        ),
        'message', 'Pipeline connection successful'
    );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Pipeline Service Accounts
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.DEVOPS.DEVOPS_LIST_PIPELINE_ACCOUNTS()
RETURNS TABLE (
    SERVICE_ACCOUNT VARCHAR,
    DEFAULT_ROLE VARCHAR,
    CREATED TIMESTAMP_NTZ,
    LAST_AUTHENTICATION TIMESTAMP_NTZ,
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
            NAME AS SERVICE_ACCOUNT,
            DEFAULT_ROLE,
            CREATED_ON AS CREATED,
            LAST_SUCCESS_LOGIN AS LAST_AUTHENTICATION,
            CASE WHEN DISABLED = 'false' THEN 'ACTIVE' ELSE 'DISABLED' END AS STATUS
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME LIKE '%_DEPLOYER'
          AND TYPE = 'SERVICE'
          AND DELETED_ON IS NULL
        ORDER BY CREATED_ON DESC
    );
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- GRANT EXECUTE PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(VARCHAR, VARCHAR, VARCHAR, ARRAY, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_AZURE_DEVOPS(VARCHAR, VARCHAR, VARCHAR, ARRAY) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GITHUB_ACTIONS(VARCHAR, VARCHAR, VARCHAR, ARRAY) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GITLAB(VARCHAR, VARCHAR, VARCHAR, ARRAY) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_SETUP_GIT_REPOSITORY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_CREATE_GIT_SECRET(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARIANT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_LOG_DEPLOYMENT_OBJECT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_DEPLOY_FROM_GIT(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_PROMOTE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR, ARRAY, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_CLONE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_ROLLBACK_DEPLOYMENT(VARCHAR, VARCHAR, TIMESTAMP_NTZ) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_GET_DEPLOYMENT_HISTORY(VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_GET_DEPLOYMENT_DETAILS(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_GENERATE_DEPLOYMENT_REPORT(DATE, DATE) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_TEST_CONNECTION() TO ROLE PUBLIC;
GRANT USAGE ON PROCEDURE ADMIN.DEVOPS.DEVOPS_LIST_PIPELINE_ACCOUNTS() TO ROLE SRS_SECURITY_ADMIN;
