export default {
  id: 'gcp-cis-1.2.0-6.2.9',
  title:
    "GCP CIS 6.2.9 Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'",
  description: `The PostgreSQL planner/optimizer is responsible to parse and verify the syntax of each
  query received by the server. If the syntax is correct a parse tree is built up else an error
  is generated. The log_parser_stats flag controls the inclusion of parser performance
  statistics in the PostgreSQL logs for each query.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to *Configuration* card
  4. Under *Database flags*, check the value of *log_parser_stats* flag is set to 'off'.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Esure the below command returns *off* for every Cloud SQL PostgreSQL database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_parser_stats")|.value'`,
  rationale: `The *log_parser_stats* flag enables a crude profiling method for logging parser performance statistics which even though can be useful for troubleshooting, it may increase the amount of logs significantly and have performance overhead. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_parser_stats* from the drop-down menu and set appropriate value.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Configure the *log_parser_stats* database flag for every Cloud SQL PosgreSQL database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags log_parser_stats=off

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT`,
    `https://www.postgresql.org/docs/10/parser-stage.html`,
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
                    equal: 'log_parser_stats',
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
      },
    ],
  },
}
