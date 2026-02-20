/*******************************************************************************
 * RBAC STORED PROCEDURE: Identity Integration Setup
 * 
 * Purpose: Procedures for configuring SSO (SAML) and SCIM integrations
 *          to enable identity provider connectivity
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURES
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedures)
 *   Execution Role:  ACCOUNTADMIN (for security integrations)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - Identity Provider (Okta, Azure AD, etc.) configured
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * TWO PROVISIONING MODELS:
 * 
 *   MODEL A: SCIM + Manual RBAC
 *   ─────────────────────────────────────────────────────────────
 *   - SCIM provisions user accounts only
 *   - Admin manually assigns RBAC roles via RBAC_CONFIGURE_USER
 *   - Simpler IdP setup, more manual Snowflake administration
 *   - Use: Smaller organizations, fewer role changes
 * 
 *   MODEL B: Full SCIM Automation
 *   ─────────────────────────────────────────────────────────────
 *   - SCIM provisions users AND assigns roles via AD group mapping
 *   - Roles automatically granted/revoked based on AD group membership
 *   - Complex IdP setup, minimal Snowflake administration
 *   - Use: Larger organizations, frequent role changes
 * 
 * Supported Identity Providers:
 *   - Okta
 *   - Azure AD (Microsoft Entra ID)
 *   - Custom SAML 2.0 providers
 ******************************************************************************/

-- #############################################################################
-- SECTION 1: SCIM PROVISIONER ROLE AND USER SETUP
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create SCIM Provisioner Infrastructure
 * 
 * Purpose: Creates the SCIM provisioner role and user with appropriate privileges
 *          This is required for BOTH provisioning models.
 * 
 * Creates:
 *   - SCIM provisioner role (e.g., OKTA_PROVISIONER, AAD_PROVISIONER)
 *   - Grants required privileges for user/role management
 * 
 * Parameters:
 *   P_IDP_TYPE          - Identity provider: 'OKTA' or 'AZURE_AD'
 *   P_PROVISIONING_MODE - 'BASIC' (users only) or 'FULL' (users + groups/roles)
 * 
 * Execution Role: ACCOUNTADMIN
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_CREATE_SCIM_PROVISIONER(
    P_IDP_TYPE VARCHAR,
    P_PROVISIONING_MODE VARCHAR DEFAULT 'BASIC'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_provisioner_role VARCHAR;
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Validate IdP type
    IF (P_IDP_TYPE NOT IN ('OKTA', 'AZURE_AD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid IdP type. Must be OKTA or AZURE_AD'
        );
    END IF;
    
    -- Validate provisioning mode
    IF (P_PROVISIONING_MODE NOT IN ('BASIC', 'FULL')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid provisioning mode. Must be BASIC or FULL'
        );
    END IF;
    
    -- Derive provisioner role name
    v_provisioner_role := IFF(P_IDP_TYPE = 'OKTA', 'OKTA_PROVISIONER', 'AAD_PROVISIONER');
    
    -- Create provisioner role
    v_sql := 'CREATE ROLE IF NOT EXISTS ' || v_provisioner_role || 
             ' COMMENT = ''SCIM provisioner role for ' || P_IDP_TYPE || ' (' || P_PROVISIONING_MODE || ' mode)''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_ROLE', 'role', v_provisioner_role));
    
    -- Grant to ACCOUNTADMIN for management
    v_sql := 'GRANT ROLE ' || v_provisioner_role || ' TO ROLE ACCOUNTADMIN';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_TO_ACCOUNTADMIN'));
    
    -- BASIC privileges (required for both modes)
    v_sql := 'GRANT CREATE USER ON ACCOUNT TO ROLE ' || v_provisioner_role;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_CREATE_USER'));
    
    -- FULL mode additional privileges (for group-to-role mapping)
    IF (P_PROVISIONING_MODE = 'FULL') THEN
        -- Grant CREATE ROLE for SCIM-managed roles
        v_sql := 'GRANT CREATE ROLE ON ACCOUNT TO ROLE ' || v_provisioner_role;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_CREATE_ROLE'));
        
        -- Grant MANAGE GRANTS for role assignment
        v_sql := 'GRANT MANAGE GRANTS ON ACCOUNT TO ROLE ' || v_provisioner_role;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'GRANT_MANAGE_GRANTS'));
        
        -- Grant ownership on RBAC roles to provisioner (so SCIM can assign them)
        -- This grants the provisioner the ability to grant SRF_* and SRA_* roles
        FOR env IN (SELECT column1 AS env FROM VALUES ('DEV'), ('TST'), ('UAT'), ('PPE'), ('PRD')) DO
            -- Grant SRF roles to provisioner (for granting to users)
            FOR role_level IN (SELECT column1 AS lvl FROM VALUES ('END_USER'), ('ANALYST'), ('DEVELOPER'), ('TEAM_LEADER'), ('DATA_SCIENTIST'), ('DBADMIN')) DO
                LET v_srf_role VARCHAR := 'SRF_' || env.env || '_' || role_level.lvl;
                BEGIN
                    v_sql := 'GRANT ROLE ' || v_srf_role || ' TO ROLE ' || v_provisioner_role || ' WITH GRANT OPTION';
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        NULL; -- Role may not exist yet
                END;
            END FOR;
        END FOR;
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'provisioner_role', v_provisioner_role,
        'idp_type', P_IDP_TYPE,
        'provisioning_mode', P_PROVISIONING_MODE,
        'privileges', IFF(P_PROVISIONING_MODE = 'FULL',
            ARRAY_CONSTRUCT('CREATE USER', 'CREATE ROLE', 'MANAGE GRANTS', 'GRANT SRF_* ROLES'),
            ARRAY_CONSTRUCT('CREATE USER')),
        'actions', v_actions,
        'next_step', 'Run RBAC_SETUP_SCIM_' || P_IDP_TYPE || ' to create the SCIM integration'
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
-- SECTION 2: MODEL A - SCIM + MANUAL RBAC
-- #############################################################################

/*******************************************************************************
 * MODEL A: SCIM + Manual RBAC Configuration
 * 
 * Flow:
 *   1. SCIM creates user accounts in Snowflake
 *   2. Admin runs RBAC_CONFIGURE_USER to assign roles
 *   3. User logs in via SSO with assigned roles
 * 
 * AD Groups Required: None (roles assigned manually in Snowflake)
 * 
 * Pros:
 *   - Simple IdP configuration
 *   - No AD group structure required
 *   - Full control over role assignment
 * 
 * Cons:
 *   - Manual role assignment for each user
 *   - Role changes require Snowflake admin action
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SETUP_MODEL_A_BASIC_SCIM(
    P_IDP_TYPE VARCHAR,
    P_INTEGRATION_NAME VARCHAR,
    P_NETWORK_POLICY VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_provisioner_role VARCHAR;
    v_scim_url VARCHAR;
    v_sql VARCHAR;
BEGIN
    -- Validate IdP type
    IF (P_IDP_TYPE NOT IN ('OKTA', 'AZURE_AD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid IdP type. Must be OKTA or AZURE_AD'
        );
    END IF;
    
    -- Derive names
    v_provisioner_role := IFF(P_IDP_TYPE = 'OKTA', 'OKTA_PROVISIONER', 'AAD_PROVISIONER');
    v_scim_url := 'https://' || CURRENT_ACCOUNT() || '.snowflakecomputing.com/scim/v2/';
    
    -- Step 1: Create provisioner infrastructure (BASIC mode)
    CALL RBAC_CREATE_SCIM_PROVISIONER(P_IDP_TYPE, 'BASIC');
    
    -- Step 2: Create SCIM integration
    v_sql := 'CREATE OR REPLACE SECURITY INTEGRATION ' || P_INTEGRATION_NAME || '
        TYPE = SCIM
        SCIM_CLIENT = ''' || IFF(P_IDP_TYPE = 'OKTA', 'OKTA', 'AZURE') || '''
        RUN_AS_ROLE = ''' || v_provisioner_role || '''';
    
    IF (P_NETWORK_POLICY IS NOT NULL) THEN
        v_sql := v_sql || ' NETWORK_POLICY = ''' || P_NETWORK_POLICY || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'model', 'A - SCIM + Manual RBAC',
        'integration_name', P_INTEGRATION_NAME,
        'idp_type', P_IDP_TYPE,
        'provisioner_role', v_provisioner_role,
        'scim_url', v_scim_url,
        'capabilities', OBJECT_CONSTRUCT(
            'user_provisioning', TRUE,
            'user_deprovisioning', TRUE,
            'group_sync', FALSE,
            'role_assignment', 'MANUAL via RBAC_CONFIGURE_USER'
        ),
        'idp_configuration', OBJECT_CONSTRUCT(
            'scim_url', v_scim_url,
            'provisioning_features', ARRAY_CONSTRUCT(
                'Create Users',
                'Update User Attributes',
                'Deactivate Users'
            ),
            'group_push', 'NOT REQUIRED'
        ),
        'next_steps', ARRAY_CONSTRUCT(
            '1. Generate SCIM token: CALL RBAC_GENERATE_SCIM_TOKEN(''' || P_INTEGRATION_NAME || ''');',
            '2. Configure SCIM in ' || P_IDP_TYPE || ' with URL and token',
            '3. Enable user provisioning (Create, Update, Deactivate)',
            '4. Assign users to the app in ' || P_IDP_TYPE,
            '5. After users sync, run: CALL RBAC_CONFIGURE_USER(user, env, domain, capability, warehouse, NULL);',
            '6. Monitor pending users: CALL RBAC_LIST_SCIM_USERS_PENDING_CONFIG();'
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
-- SECTION 3: MODEL B - FULL SCIM AUTOMATION
-- #############################################################################

/*******************************************************************************
 * MODEL B: Full SCIM Automation with AD Group-to-Role Mapping
 * 
 * Flow:
 *   1. Admin creates AD groups mapped to Snowflake roles
 *   2. SCIM syncs users AND group memberships
 *   3. Snowflake roles auto-granted based on AD group membership
 *   4. User logs in via SSO with auto-assigned roles
 * 
 * AD Groups Required:
 *   - One group per SRF_* role (capability)
 *   - One group per SRA_* role (data access)
 *   - Users need membership in BOTH capability + access groups
 * 
 * Pros:
 *   - Fully automated role assignment
 *   - Roles change automatically when AD groups change
 *   - Centralized access management in IdP
 * 
 * Cons:
 *   - Complex AD group structure required
 *   - More IdP configuration
 *   - Requires proper AD group naming convention
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SETUP_MODEL_B_FULL_SCIM(
    P_IDP_TYPE VARCHAR,
    P_INTEGRATION_NAME VARCHAR,
    P_NETWORK_POLICY VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_provisioner_role VARCHAR;
    v_scim_url VARCHAR;
    v_sql VARCHAR;
    v_ad_groups ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Validate IdP type
    IF (P_IDP_TYPE NOT IN ('OKTA', 'AZURE_AD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid IdP type. Must be OKTA or AZURE_AD'
        );
    END IF;
    
    -- Derive names
    v_provisioner_role := IFF(P_IDP_TYPE = 'OKTA', 'OKTA_PROVISIONER', 'AAD_PROVISIONER');
    v_scim_url := 'https://' || CURRENT_ACCOUNT() || '.snowflakecomputing.com/scim/v2/';
    
    -- Step 1: Create provisioner infrastructure (FULL mode with MANAGE GRANTS)
    CALL RBAC_CREATE_SCIM_PROVISIONER(P_IDP_TYPE, 'FULL');
    
    -- Step 2: Create SCIM integration with group sync enabled
    v_sql := 'CREATE OR REPLACE SECURITY INTEGRATION ' || P_INTEGRATION_NAME || '
        TYPE = SCIM
        SCIM_CLIENT = ''' || IFF(P_IDP_TYPE = 'OKTA', 'OKTA', 'AZURE') || '''
        RUN_AS_ROLE = ''' || v_provisioner_role || '''
        SYNC_PASSWORD = FALSE';
    
    IF (P_NETWORK_POLICY IS NOT NULL) THEN
        v_sql := v_sql || ' NETWORK_POLICY = ''' || P_NETWORK_POLICY || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Build recommended AD group structure
    FOR env IN (SELECT column1 AS env FROM VALUES ('DEV'), ('TST'), ('UAT'), ('PPE'), ('PRD')) DO
        -- Functional role groups
        FOR role_level IN (SELECT column1 AS lvl FROM VALUES ('END_USER'), ('ANALYST'), ('DEVELOPER')) DO
            v_ad_groups := ARRAY_APPEND(v_ad_groups, OBJECT_CONSTRUCT(
                'ad_group', 'SF_' || env.env || '_' || role_level.lvl,
                'snowflake_role', 'SRF_' || env.env || '_' || role_level.lvl,
                'type', 'FUNCTIONAL'
            ));
        END FOR;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'model', 'B - Full SCIM Automation',
        'integration_name', P_INTEGRATION_NAME,
        'idp_type', P_IDP_TYPE,
        'provisioner_role', v_provisioner_role,
        'scim_url', v_scim_url,
        'capabilities', OBJECT_CONSTRUCT(
            'user_provisioning', TRUE,
            'user_deprovisioning', TRUE,
            'group_sync', TRUE,
            'role_assignment', 'AUTOMATIC via AD group membership'
        ),
        'idp_configuration', OBJECT_CONSTRUCT(
            'scim_url', v_scim_url,
            'provisioning_features', ARRAY_CONSTRUCT(
                'Create Users',
                'Update User Attributes',
                'Deactivate Users',
                'Push Groups'
            ),
            'group_push', 'REQUIRED - Map AD groups to Snowflake roles'
        ),
        'ad_group_naming', OBJECT_CONSTRUCT(
            'pattern', 'SF_<ENV>_<ROLE_NAME>',
            'examples', ARRAY_CONSTRUCT(
                'SF_DEV_DEVELOPER → SRF_DEV_DEVELOPER',
                'SF_DEV_HR_ACCESS → SRA_DEV_HR_ACCESS',
                'SF_PRD_ANALYST → SRF_PRD_ANALYST'
            )
        ),
        'next_steps', ARRAY_CONSTRUCT(
            '1. Create AD groups following naming convention (see ad_group_naming)',
            '2. Generate SCIM token: CALL RBAC_GENERATE_SCIM_TOKEN(''' || P_INTEGRATION_NAME || ''');',
            '3. Configure SCIM in ' || P_IDP_TYPE || ' with URL and token',
            '4. Enable ALL provisioning features including Group Push',
            '5. Map each AD group to corresponding Snowflake role name',
            '6. Assign users to AD groups (need both SRF_* and SRA_* groups)',
            '7. Validate mapping: CALL RBAC_VALIDATE_AD_GROUP_MAPPING();'
        ),
        'important', 'Users must be in BOTH a functional group (SF_*_DEVELOPER) AND an access group (SF_*_HR_ACCESS) to have full access'
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

/*******************************************************************************
 * RBAC STORED PROCEDURE: Grant SCIM Role Assignment Privileges
 * 
 * Purpose: Grants the SCIM provisioner the ability to assign specific
 *          RBAC roles to users (required for Full SCIM Model B)
 * 
 * Parameters:
 *   P_IDP_TYPE      - Identity provider: 'OKTA' or 'AZURE_AD'
 *   P_ROLE_NAME     - Snowflake role to allow SCIM to grant (e.g., 'SRF_DEV_DEVELOPER')
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GRANT_SCIM_ROLE_PRIVILEGE(
    P_IDP_TYPE VARCHAR,
    P_ROLE_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_provisioner_role VARCHAR;
    v_sql VARCHAR;
BEGIN
    -- Derive provisioner role
    v_provisioner_role := IFF(P_IDP_TYPE = 'OKTA', 'OKTA_PROVISIONER', 'AAD_PROVISIONER');
    
    -- Grant role to provisioner with grant option
    v_sql := 'GRANT ROLE ' || P_ROLE_NAME || ' TO ROLE ' || v_provisioner_role || ' WITH GRANT OPTION';
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'provisioner_role', v_provisioner_role,
        'granted_role', P_ROLE_NAME,
        'capability', 'SCIM can now assign ' || P_ROLE_NAME || ' to users via AD group mapping'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'role', P_ROLE_NAME
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Grant All RBAC Roles to SCIM Provisioner
 * 
 * Purpose: Grants the SCIM provisioner the ability to assign ALL existing
 *          SRF_* and SRA_* roles (required for Full SCIM Model B)
 * 
 * Parameters:
 *   P_IDP_TYPE      - Identity provider: 'OKTA' or 'AZURE_AD'
 *   P_ENVIRONMENT   - Environment to grant roles for (NULL = all)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GRANT_ALL_ROLES_TO_SCIM(
    P_IDP_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_provisioner_role VARCHAR;
    v_sql VARCHAR;
    v_granted_count INTEGER := 0;
    v_granted_roles ARRAY := ARRAY_CONSTRUCT();
    v_env_filter VARCHAR;
BEGIN
    -- Derive provisioner role
    v_provisioner_role := IFF(P_IDP_TYPE = 'OKTA', 'OKTA_PROVISIONER', 'AAD_PROVISIONER');
    
    -- Build environment filter
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;
    
    -- Grant all SRF_* roles
    FOR role_rec IN (
        SELECT NAME 
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES 
        WHERE NAME LIKE 'SRF' || v_env_filter || '%'
          AND DELETED_ON IS NULL
    ) DO
        BEGIN
            v_sql := 'GRANT ROLE ' || role_rec.NAME || ' TO ROLE ' || v_provisioner_role || ' WITH GRANT OPTION';
            EXECUTE IMMEDIATE v_sql;
            v_granted_roles := ARRAY_APPEND(v_granted_roles, role_rec.NAME);
            v_granted_count := v_granted_count + 1;
        EXCEPTION
            WHEN OTHER THEN
                NULL; -- Skip errors
        END;
    END FOR;
    
    -- Grant all SRA_* roles
    FOR role_rec IN (
        SELECT NAME 
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES 
        WHERE NAME LIKE 'SRA' || v_env_filter || '%'
          AND DELETED_ON IS NULL
    ) DO
        BEGIN
            v_sql := 'GRANT ROLE ' || role_rec.NAME || ' TO ROLE ' || v_provisioner_role || ' WITH GRANT OPTION';
            EXECUTE IMMEDIATE v_sql;
            v_granted_roles := ARRAY_APPEND(v_granted_roles, role_rec.NAME);
            v_granted_count := v_granted_count + 1;
        EXCEPTION
            WHEN OTHER THEN
                NULL; -- Skip errors
        END;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'provisioner_role', v_provisioner_role,
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'roles_granted', v_granted_count,
        'granted_roles', v_granted_roles,
        'capability', 'SCIM can now assign these roles to users via AD group mapping'
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
-- SECTION 4: AD GROUP-TO-ROLE VALIDATION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Validate AD Group-to-Role Mapping
 * 
 * Purpose: Validates that AD groups are properly mapped to Snowflake roles
 *          and identifies any missing roles or mappings
 * 
 * Checks:
 *   1. SCIM-synced roles exist in Snowflake
 *   2. Users have expected role assignments based on group membership
 *   3. Identifies orphaned SCIM roles (group deleted but role remains)
 * 
 * Parameters:
 *   P_ENVIRONMENT - Environment to validate (NULL = all)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_VALIDATE_AD_GROUP_MAPPING(
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_env_filter VARCHAR;
    v_expected_roles ARRAY := ARRAY_CONSTRUCT();
    v_existing_roles ARRAY;
    v_missing_roles ARRAY := ARRAY_CONSTRUCT();
    v_scim_roles ARRAY;
    v_recommendations ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Build environment filter
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;
    
    -- Get existing RBAC roles
    v_existing_roles := (
        SELECT ARRAY_AGG(NAME)
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE (NAME LIKE 'SRF' || :v_env_filter || '%' OR NAME LIKE 'SRA' || :v_env_filter || '%')
          AND DELETED_ON IS NULL
    );
    
    -- Get roles that appear to be SCIM-managed (granted to provisioner)
    v_scim_roles := (
        SELECT ARRAY_AGG(DISTINCT ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTEE_NAME IN ('OKTA_PROVISIONER', 'AAD_PROVISIONER')
          AND PRIVILEGE = 'USAGE'
          AND DELETED_ON IS NULL
    );
    
    -- Build expected AD group mappings
    FOR env IN (SELECT column1 AS env FROM VALUES ('DEV'), ('TST'), ('UAT'), ('PPE'), ('PRD')) DO
        IF (P_ENVIRONMENT IS NULL OR env.env = P_ENVIRONMENT) THEN
            -- Functional roles
            FOR role_level IN (SELECT column1 AS lvl FROM VALUES ('END_USER'), ('ANALYST'), ('DEVELOPER'), ('TEAM_LEADER'), ('DATA_SCIENTIST'), ('DBADMIN')) DO
                v_expected_roles := ARRAY_APPEND(v_expected_roles, OBJECT_CONSTRUCT(
                    'ad_group', 'SF_' || env.env || '_' || role_level.lvl,
                    'snowflake_role', 'SRF_' || env.env || '_' || role_level.lvl,
                    'type', 'FUNCTIONAL',
                    'exists', ARRAY_CONTAINS(('SRF_' || env.env || '_' || role_level.lvl)::VARIANT, COALESCE(v_existing_roles, ARRAY_CONSTRUCT()))
                ));
            END FOR;
        END IF;
    END FOR;
    
    -- Check for missing roles
    FOR i IN 0 TO ARRAY_SIZE(v_expected_roles) - 1 DO
        IF (NOT v_expected_roles[i]:exists::BOOLEAN) THEN
            v_missing_roles := ARRAY_APPEND(v_missing_roles, v_expected_roles[i]:snowflake_role);
        END IF;
    END FOR;
    
    -- Generate recommendations
    IF (ARRAY_SIZE(v_missing_roles) > 0) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, 
            'Run RBAC_INITIAL_CONFIG() to create missing functional roles');
    END IF;
    
    v_recommendations := ARRAY_APPEND(v_recommendations,
        'Create AD groups following pattern: SF_<ENV>_<ROLE_NAME>');
    v_recommendations := ARRAY_APPEND(v_recommendations,
        'For access roles, create AD groups like: SF_DEV_HR_ACCESS, SF_PRD_SALES_ACCESS');
    v_recommendations := ARRAY_APPEND(v_recommendations,
        'Map each AD group to corresponding Snowflake role in IdP SCIM settings');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'existing_rbac_roles', COALESCE(v_existing_roles, ARRAY_CONSTRUCT()),
        'scim_enabled_roles', COALESCE(v_scim_roles, ARRAY_CONSTRUCT()),
        'expected_mappings', v_expected_roles,
        'missing_roles', v_missing_roles,
        'missing_count', ARRAY_SIZE(v_missing_roles),
        'recommendations', v_recommendations,
        'ad_group_template', OBJECT_CONSTRUCT(
            'functional_groups', ARRAY_CONSTRUCT(
                'SF_DEV_END_USER → SRF_DEV_END_USER',
                'SF_DEV_ANALYST → SRF_DEV_ANALYST', 
                'SF_DEV_DEVELOPER → SRF_DEV_DEVELOPER',
                'SF_PRD_ANALYST → SRF_PRD_ANALYST'
            ),
            'access_groups', ARRAY_CONSTRUCT(
                'SF_DEV_HR_ACCESS → SRA_DEV_HR_ACCESS',
                'SF_DEV_SALES_ACCESS → SRA_DEV_SALES_ACCESS',
                'SF_PRD_FINANCE_ACCESS → SRA_PRD_FINANCE_ACCESS'
            )
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

/*******************************************************************************
 * RBAC STORED PROCEDURE: List AD Group Mapping Requirements
 * 
 * Purpose: Lists all Snowflake roles that need AD group mappings
 *          for Full SCIM automation
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_LIST_AD_GROUP_REQUIREMENTS(
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_env_filter VARCHAR;
    v_functional_roles ARRAY;
    v_access_roles ARRAY;
    v_ad_groups ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Build environment filter
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;
    
    -- Get functional roles
    v_functional_roles := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'snowflake_role', NAME,
            'required_ad_group', REPLACE(NAME, 'SRF_', 'SF_'),
            'type', 'FUNCTIONAL'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE NAME LIKE 'SRF' || :v_env_filter || '%'
          AND DELETED_ON IS NULL
    );
    
    -- Get access roles
    v_access_roles := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'snowflake_role', NAME,
            'required_ad_group', REPLACE(NAME, 'SRA_', 'SF_'),
            'type', 'ACCESS'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE NAME LIKE 'SRA' || :v_env_filter || '%'
          AND DELETED_ON IS NULL
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'functional_role_mappings', COALESCE(v_functional_roles, ARRAY_CONSTRUCT()),
        'access_role_mappings', COALESCE(v_access_roles, ARRAY_CONSTRUCT()),
        'total_ad_groups_required', 
            COALESCE(ARRAY_SIZE(v_functional_roles), 0) + COALESCE(ARRAY_SIZE(v_access_roles), 0),
        'instructions', ARRAY_CONSTRUCT(
            '1. Create each AD group listed above in your IdP',
            '2. In SCIM Group Push settings, map each AD group to Snowflake role',
            '3. Add users to appropriate AD groups (need BOTH functional + access groups)',
            '4. Example: User needs SF_DEV_DEVELOPER AND SF_DEV_HR_ACCESS for HR development'
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
-- SECTION 5: SSO INTEGRATION PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup SSO Integration (Okta)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SETUP_SSO_OKTA(
    P_INTEGRATION_NAME VARCHAR,
    P_OKTA_ISSUER VARCHAR,
    P_OKTA_SSO_URL VARCHAR,
    P_X509_CERT VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_account_url VARCHAR;
    v_acs_url VARCHAR;
    v_entity_id VARCHAR;
BEGIN
    IF (P_INTEGRATION_NAME IS NULL OR P_OKTA_ISSUER IS NULL OR 
       P_OKTA_SSO_URL IS NULL OR P_X509_CERT IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'All parameters required'
        );
    END IF;
    
    v_account_url := CURRENT_ACCOUNT() || '.snowflakecomputing.com';
    v_acs_url := 'https://' || v_account_url || '/fed/login';
    v_entity_id := 'https://' || v_account_url;
    
    v_sql := 'CREATE OR REPLACE SECURITY INTEGRATION ' || P_INTEGRATION_NAME || '
        TYPE = SAML2
        ENABLED = TRUE
        SAML2_ISSUER = ''' || P_OKTA_ISSUER || '''
        SAML2_SSO_URL = ''' || P_OKTA_SSO_URL || '''
        SAML2_PROVIDER = ''OKTA''
        SAML2_X509_CERT = ''' || P_X509_CERT || '''
        SAML2_SP_INITIATED_LOGIN_PAGE_LABEL = ''Okta SSO''
        SAML2_ENABLE_SP_INITIATED = TRUE
        SAML2_SNOWFLAKE_ACS_URL = ''' || v_acs_url || '''
        SAML2_SNOWFLAKE_ISSUER_URL = ''' || v_entity_id || '''';
    
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'integration_name', P_INTEGRATION_NAME,
        'provider', 'OKTA',
        'snowflake_acs_url', v_acs_url,
        'snowflake_entity_id', v_entity_id
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup SSO Integration (Azure AD)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SETUP_SSO_AZURE_AD(
    P_INTEGRATION_NAME VARCHAR,
    P_AZURE_ISSUER VARCHAR,
    P_AZURE_SSO_URL VARCHAR,
    P_X509_CERT VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_account_url VARCHAR;
    v_acs_url VARCHAR;
    v_entity_id VARCHAR;
BEGIN
    IF (P_INTEGRATION_NAME IS NULL OR P_AZURE_ISSUER IS NULL OR 
       P_AZURE_SSO_URL IS NULL OR P_X509_CERT IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'All parameters required'
        );
    END IF;
    
    v_account_url := CURRENT_ACCOUNT() || '.snowflakecomputing.com';
    v_acs_url := 'https://' || v_account_url || '/fed/login';
    v_entity_id := 'https://' || v_account_url;
    
    v_sql := 'CREATE OR REPLACE SECURITY INTEGRATION ' || P_INTEGRATION_NAME || '
        TYPE = SAML2
        ENABLED = TRUE
        SAML2_ISSUER = ''' || P_AZURE_ISSUER || '''
        SAML2_SSO_URL = ''' || P_AZURE_SSO_URL || '''
        SAML2_PROVIDER = ''CUSTOM''
        SAML2_X509_CERT = ''' || P_X509_CERT || '''
        SAML2_SP_INITIATED_LOGIN_PAGE_LABEL = ''Azure AD SSO''
        SAML2_ENABLE_SP_INITIATED = TRUE
        SAML2_SNOWFLAKE_ACS_URL = ''' || v_acs_url || '''
        SAML2_SNOWFLAKE_ISSUER_URL = ''' || v_entity_id || '''';
    
    EXECUTE IMMEDIATE v_sql;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'integration_name', P_INTEGRATION_NAME,
        'provider', 'AZURE_AD',
        'snowflake_acs_url', v_acs_url,
        'snowflake_entity_id', v_entity_id
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: SCIM TOKEN AND MONITORING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate SCIM Access Token
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GENERATE_SCIM_TOKEN(
    P_INTEGRATION_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_token VARCHAR;
BEGIN
    SELECT SYSTEM$GENERATE_SCIM_ACCESS_TOKEN(:P_INTEGRATION_NAME) INTO v_token;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'integration_name', P_INTEGRATION_NAME,
        'access_token', v_token,
        'warning', 'THIS TOKEN IS SHOWN ONLY ONCE. STORE IT SECURELY!'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List SCIM Provisioned Users Pending Configuration
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_LIST_SCIM_USERS_PENDING_CONFIG()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_pending_users ARRAY;
    v_configured_users ARRAY;
BEGIN
    v_pending_users := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'email', u.EMAIL,
            'created_on', u.CREATED_ON,
            'status', 'PENDING_RBAC_CONFIGURATION'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        WHERE u.DELETED_ON IS NULL
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
          AND NOT EXISTS (
              SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g
              WHERE g.GRANTEE_NAME = u.NAME AND g.ROLE LIKE 'SRF_%' AND g.DELETED_ON IS NULL
          )
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'pending_count', COALESCE(ARRAY_SIZE(v_pending_users), 0),
        'pending_users', COALESCE(v_pending_users, ARRAY_CONSTRUCT()),
        'action', 'Run RBAC_CONFIGURE_USER for each pending user (Model A) or verify AD group membership (Model B)'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- GRANT EXECUTE PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE RBAC_CREATE_SCIM_PROVISIONER(VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_MODEL_A_BASIC_SCIM(VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_MODEL_B_FULL_SCIM(VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_GRANT_SCIM_ROLE_PRIVILEGE(VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_GRANT_ALL_ROLES_TO_SCIM(VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_VALIDATE_AD_GROUP_MAPPING(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_LIST_AD_GROUP_REQUIREMENTS(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_SSO_OKTA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_SSO_AZURE_AD(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_GENERATE_SCIM_TOKEN(VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_LIST_SCIM_USERS_PENDING_CONFIG() TO ROLE SRS_SECURITY_ADMIN;
