export default {
  id: 'gcp-cis-1.2.0-6.2.13',
  title:
    "GCP CIS 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately",
  description: `The log_min_messages flag defines the minimum message severity level that is considered
  as an error statement. Messages for error statements are logged with the SQL statement.
  Valid values include DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR,
  LOG, FATAL, and PANIC. Each severity level includes the subsequent levels mentioned above.

  Note: To effectively turn off logging failing statements, set this parameter to PANIC.

  ERROR is considered the best practice setting. Changes should only be made in accordance
  with the organization's logging policy.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page.
  3. Go to the *Configuration* card.
  4. Under *Database flags*, check the value of *log_min_messages* flag is in accordance with the organization's logging policy.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:


          gcloud sql instances list

  2. Use the below command for every Cloud SQL PostgreSQL database instance to verify that the value of *log_min_messages* is in accordance with the organization's logging policy.

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_min_messages")|.value'`,
  rationale: `Auditing helps in troubleshooting operational problems and also permits forensic analysis. If *log_min_error_statement* is not set to the correct value, messages may not be classified as error messages appropriately. Considering general log messages as error messages would make it difficult to find actual errors, while considering only stricter severity levels as error messages may skip actual errors to log their SQL statements. The *log_min_messages* flag should be set in accordance with the organization's logging policy. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click Edit.
  4. Scroll down to the Flags section.
  5. To set a flag that has not been set on the instance before, click Add item, choose the flag log_min_messages from the drop-down menu and set appropriate value.
  6. Click Save to save the changes.
  7. Confirm the changes under Flags on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list

  2. Configure the log_min_messages database flag for every Cloud SQL PosgreSQL database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags log_min_messages=<DEBUG5|DEBUG4|DEBUG3|DEBUG2|DEBUG1|INFO|NOTICE|WARNING|ERROR|LOG|FATAL|PANIC>

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHEN`,
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
              equal: 'log_min_messages',
            },
            {
              path: '[*].value',
              in: [
                'DEBUG5',
                'DEBUG4',
                'DEBUG3',
                'DEBUG2',
                'DEBUG1',
                'INFO',
                'NOTICE',
                'WARNING',
                'ERROR',
                'LOG',
                'FATAL',
                'PANIC',
              ],
            },
          ],
        },
      },
    ],
  },
}
