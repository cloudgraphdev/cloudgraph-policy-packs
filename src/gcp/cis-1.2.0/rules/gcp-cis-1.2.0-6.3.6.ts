export default {
  id: 'gcp-cis-1.2.0-6.3.6',
  title:
    "GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'",
  description: `It is recommended to set 3625 (trace flag) database flag for Cloud SQL SQL Server
  instance to off.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag *3625* that has been set is listed under the *Database flags* section.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Ensure the below command returns *off* for every Cloud SQL SQL Server database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="3625")|.value'`,
  rationale: `Trace flags are frequently used to diagnose performance issues or to debug stored procedures or complex computer systems, but they may also be recommended by Microsoft Support to address behavior that is negatively impacting a specific workload. All documented trace flags and those recommended by Microsoft Support are fully supported in a production environment when used as directed. *3625(trace log)* Limits the amount of information returned to users who are not members of the sysadmin fixed server role, by masking the parameters of some error messages using '******'. This can help prevent disclosure of sensitive information, hence this is recommended to disable this flag. This recommendation is applicable to SQL Server database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the SQL Server instance for which you want to enable to database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *3625* from the drop-down menu, and set its value to *off*.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Configure the *3625* database flag for every Cloud SQL SQL Server database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags "3625=off"

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/sqlserver/flags`,
    `https://docs.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-traceon-trace-flags-transact-sql?view=sql-server-ver15#trace-flags`,
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
  severity: 'unknown',
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
              equal: '3625 (trace flag)',
            },
            {
              path: '[*].value',
              equal: 'off',
            },
          ],
        },
      },
    ],
  },
}
