export default {
  id: 'gcp-cis-1.3.0-6.3.4',
  title:
    "GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured",
  description: `It is recommended that, user options database flag for Cloud SQL SQL Server instance
  should not be configured.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag *user options* that has been set is not listed under the *Database flags* section.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Ensure the below command returns empty result for every Cloud SQL SQL Server database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="user options")|.value'`,
  rationale: `The *user options* option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate).

  A user can override these defaults by using the SET statement. You can configure user options dynamically for new logins. After you change the setting of user options, new login sessions use the new setting; current login sessions are not affected. This recommendation is applicable to SQL Server database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the SQL Server instance for which you want to enable to database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. Click the X next *user options* flag shown
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

  gcloud sql instances list

  2. Clear the *user options* database flag for every Cloud SQL SQL Server database instance using either of the below commands.

          1.Clearing all flags to their default value

          gcloud sql instances patch [INSTANCE_NAME] --clear-database-flags

          OR

          2. To clear only 'user options' database flag, configure the database flag by overriding the 'user options'. Exclude 'user options' flag and its value, and keep all other flags you want to configure.

          gcloud sql instances patch [INSTANCE_NAME] --database-flags [FLAG1=VALUE1,FLAG2=VALUE2]


  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    'https://cloud.google.com/sql/docs/sqlserver/flags',
    'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-user-options-server-configuration-option?view=sql-server-ver15',
    'https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018- 03-09/finding/V-79335',
  ],
  gql: `{
    querygcpSqlInstance(filter:{ databaseVersion: {regexp:  "/SQLSERVER*/"}}){
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
  exclude: { not: { path: '@.databaseVersion', match: /SQLSERVER*/ } },
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.settings.databaseFlags',
        isEmpty: true,
      },
      {
        path: '@.settings.databaseFlags',
        array_all: {
          not: {
            and: [
              {
                path: '[*].name',
                equal: 'user options',
              },
              {
                path: '[*].value',
                isEmpty: false,
              },
            ],
          },
        },
      },
    ],
  },
}
