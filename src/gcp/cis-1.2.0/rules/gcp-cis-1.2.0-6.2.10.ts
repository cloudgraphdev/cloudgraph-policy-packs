export default {
  id: 'gcp-cis-1.2.0-6.2.10',
  title:
    "GCP CIS 6.2.10 Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'",
  description: `The same SQL query can be excuted in multiple ways and still produce different results.
  The PostgreSQL planner/optimizer is responsible to create an optimal execution plan for
  each query. The log_planner_stats flag controls the inclusion of PostgreSQL planner
  performance statistics in the PostgreSQL logs for each query.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to *Configuration* card
  4. Under *Database flags*, check the value of *log_planner_stats* flag is set to 'off'.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Ensure the below command returns *off* for every Cloud SQL PostgreSQL database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_planner_stats")|.value'`,
  rationale: `The *log_planner_stats* flag enables a crude profiling method for logging PostgreSQL planner performance statistics which even though can be useful for troubleshooting, it may increase the amount of logs significantly and have performance overhead. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_planner_stats* from the drop-down menu and set appropriate value.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Configure the *log_planner_stats* database flag for every Cloud SQL PosgreSQL database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags log_planner_stats=off

  **Note:** This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-statistics.html#RUNTIME-CONFIG-STATISTICS-MONITOR`,
    `https://www.postgresql.org/docs/9.5/planner-optimizer.html`,
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
              equal: 'log_planner_stats',
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
