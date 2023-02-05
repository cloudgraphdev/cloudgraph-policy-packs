export default {
  id: 'gcp-cis-1.3.0-6.2.9',
  title:
    "GCP CIS 6.2.9 Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging",
  description: `Ensure *cloudsql.enable_pgaudit* database flag for Cloud SQL PostgreSQL instance is set 
  to *on* to allow for centralized logging.`,
  audit: `**Determining if the pgAudit Flag is set to 'on'
  
  From Console:**

  1. Go to https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Overview* page.
  3. Click *Edit*.
  4. Scroll down and expand Flags.
  5. Ensure that *cloudsql.enable_pgaudit* flag is set to *on*.

  **From Command Line:**

  Run the command by providing *<INSTANCE_NAME>*. Ensure the value of the flag is *on*.

        gcloud sql instances describe <INSTANCE_NAME> --format="json" | jq '.settings|.|.databaseFlags[]|select(.name=="cloudsql.enable_pgaudit")|.value '

  **Determine if the pgAudit extension is installed**

  1. Connect to the the server running PostgreSQL or through a SQL client of your choice.
  2. Via command line open the PostgreSQL shell by typing psql
  3. Run the following command

        SELECT * FROM pg_extension;

  4. If pgAudit is in this list. If so, it is installed.

  **Determine if Data Access Audit logs are enabled for your project and have sufficient privileges**

  1. From the homepage open the hamburger menu in the top left.
  2. Scroll down to IAM & Adminand hover over it.
  3. In the menu that opens up, select Audit Logs
  4. In the middle of the page, in the search box next to filter search for Cloud Composer API
  5. Select it, and ensure that both 'Admin Read' and 'Data Read' are checked.

  **Determine if logs are being sent to Logs Explorer**

  1. From the Google Console home page, open the hamburger menu in the top left.
  2. In the menu that pops open, scroll down to Logs Explorer under Operations.
  3. In the query box, paste the following and search

  resource.type="cloudsql_database" 
  logName="projects/<your-project-name>/logs/cloudaudit.googleapis.com%2Fdata_access"
  protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgA uditEntry"

  4. If it returns any log sources, they are correctly setup.
`,
  rationale: 'As numerous other recommendations in this section consist of turning on flags for logging purposes, your organization will need a way to manage these logs. You may have a solution already in place. If you do not, consider installing and enabling the open source pgaudit extension within PostgreSQL and enabling its corresponding flag of cloudsql.enable_pgaudit. This flag and installing the extension enables database auditing in PostgreSQL through the open-source pgAudit extension. This extension provides detailed session and object logging to comply with government, financial, & ISO standards and provides auditing capabilities to mitigate threats by monitoring security events on the instance. Enabling the flag and settings later in this recommendation will send these logs to Google Logs Explorer so that you can access them in a central location. to This recommendation is applicable only to PostgreSQL database instances.',
  remediation: `**Initialize the pgAudit flag
  
  From Console:**

  1. Go to https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its Overview page.
  3. Click *Edit*.
  4. Scroll down and expand Flags.
  5. To set a flag that has not been set on the instance before, click *Add item*.
  6. Enter *cloudsql.enable_pgaudit* for the flag name and set the flag to *on*.
  7. Click *Done*.
  8. Click *Save* to update the configuration.
  9. Confirm your changes under *Flags* on the *Overview* page.

  **From Command Line:**

  Run the below command by providing *<INSTANCE_NAME>* to enable *cloudsql.enable_pgaudit* flag.

        gcloud sql instances patch <INSTANCE_NAME> --database- flags=cloudsql.enable_pgaudit=on

  Note: *RESTART* is required to get this configuration in effect.

  **Creating the extension**

  1. Connect to the the server running PostgreSQL or through a SQL client of your choice.
  2. If SSHing to the server in the command line open the PostgreSQL shell by typing *psql*
  3. Run the following command as a superuser.

        CREATE EXTENSION pgaudit;

  **Updating the previously created pgaudit.log flag for your Logging Needs
  
  From Console:**

  Note: there are multiple options here. This command will enable logging for all databases on a server. Please see the customizing database audit logging reference for more flag options.

  1. Go to https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Overview* page.
  3. Click *Edit*.
  4. Scroll down and expand *Flags*.
  5. To set a flag that has not been set on the instance before, click *Add item*.
  6. Enter *pgaudit.log=all* for the flag name and set the flag to on.
  7. Click *Done*.
  8. Click *Save* to update the configuration.
  9. Confirm your changes under *Flags* on the *Overview* page.

  **From Command Line:**
  Run the command

        gcloud sql instances patch <INSTANCE_NAME> --database-flags cloudsql.enable_pgaudit=on,pgaudit.log=all
  
  **Determine if logs are being sent to Logs Explorer**

  1. From the Google Console home page, open the hamburger menu in the top left.
  2. In the menu that pops open, scroll down to Logs Explorer under Operations.
  3. In the query box, paste the following and search

  resource.type="cloudsql_database" logName="projects//logs/cloudaudit.googleapis.com%2Fdata_access" protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry "

        If it returns any log sources, they are correctly setup.

  **Default Value:**

  By default *cloudsql.enable_pgaudit* database flag is set to *off* and the extension is not enabled.`,
  references: [
    'https://cloud.google.com/sql/docs/postgres/flags#list-flags-postgres',
    'https://cloud.google.com/sql/docs/postgres/pg-audit#enable-auditing-flag',
    'https://cloud.google.com/sql/docs/postgres/pg-audit#customizing-database-audit-logging',
    'https://cloud.google.com/logging/docs/audit/configure-data-access#config-console-enable',
  ],
  gql: `{
    querygcpSqlInstance(filter:{ databaseVersion: {regexp:  "/POSTGRES*/"}}){
      name
      id
      __typename
      settings{
        databaseFlags{
          name
          value
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  exclude: { not: { path: '@.databaseVersion', match: /POSTGRES*/ } },
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.settings.databaseFlags',
        isEmpty: false,
      },
      {
        path: '@.settings.databaseFlags',
        array_any: {
          and: [
            {
              path: '[*].name',
              equal: 'cloudsql.enable_pgaudit',
            },
            {
              path: '[*].value',
              equal: 'on',
            },
          ],
        },
      },
    ],
  },
}
