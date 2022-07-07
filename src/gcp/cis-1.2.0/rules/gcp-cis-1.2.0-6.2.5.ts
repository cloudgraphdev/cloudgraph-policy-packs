export default {
  id: 'gcp-cis-1.2.0-6.2.5',
  title:
    "GCP CIS 6.2.5 Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
  description: `Enabling the log_duration setting causes the duration of each completed statement to be
  logged. This does not logs the text of the query and thus behaves different from the
  log_min_duration_statement flag. This parameter cannot be changed after session start.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its Instance Overview page
  3. Go to *Configuration* card
  4. Under *Database flags*, check the value of *log_duration* flag is configured as expected.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Ensure the below command returns *on* for every Cloud SQL PostgreSQL database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_duration")|.value'
  `,
  rationale: `Monitoring the time taken to execute the queries can be crucial in identifying any resource hogging queries and assessing the performance of the server. Further steps such as load balancing and use of optimized queries can be taken to ensure the performance and stability of the server. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_duration* from the drop-down menu and set the value as *on*.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Configure the *log_duration* database flag for every Cloud SQL PosgreSQL database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags log_duration=on

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT`,
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
              equal: 'log_duration',
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
