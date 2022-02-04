export default {
  id: 'gcp-cis-1.2.0-6.2.16',
  title:
    "GCP CIS 6.2.16 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)",
  description: `The log_min_duration_statement flag defines the minimum amount of execution time of a
  statement in milliseconds where the total duration of the statement is logged. Ensure that
  log_min_duration_statement is disabled, i.e., a value of - 1 is set.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page.
  3. Go to the *Configuration* card.
  4. Under* Database flags*, check that the value of *log_min_duration_statement* flag is set to *-1*.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Use the below command for every Cloud SQL PostgreSQL database instance to verify the value of *log_min_duration_statement* is set to *-1*.

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_min_duration_statement")|.value'`,
  rationale: `Logging SQL statements may include sensitive information that should not be recorded in logs. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_min_duration_statement* from the drop-down menu and set a value of *-1*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Configure the *log_min_duration_statement* flag for every Cloud SQL PosgreSQL database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags log_min_duration_statement=-1

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT`,
  ],
  gql: `{
    querygcpProject{
      id
      projectId
      __typename
      sqlInstances(filter:{ databaseVersion: {regexp:  "/POSTGRES*/"}}){
        name
        settings{
          databaseFlags{
            name
            value
          }
        }
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'medium',
  conditions: {
    path: '@',
    or: [
      {
        path: '[*].sqlInstances',
        isEmpty: true,
      },
      {
        path: '[*].sqlInstances',
        array_all: {
          path: '[*]',
          and: [
            {
              path: '[*].settings.databaseFlags',
              isEmpty: false,
            },
            {
              path: '[*].settings.databaseFlags',
              array_any: {
                and: [
                  {
                    path: '[*].name',
                    equal: 'log_min_duration_statement',
                  },
                  {
                    path: '[*].value',
                    equal: '-1',
                  },
                ],
              },
            },
          ],
        },
      },
    ],
  },
}
