export default {
  id: 'gcp-cis-1.2.0-6.2.8',
  title:
    "GCP CIS 6.2.8 Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately",
  description: `PostgreSQL logs only the IP address of the connecting hosts. The log_hostname flag
  controls the logging of hostnames in addition to the IP addresses logged. The performance
  hit is dependent on the configuration of the environment and the host name resolution
  setup. This parameter can only be set in the postgresql.conf file or on the server
  command line.`,
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to *Configuration* card
  4. Under *Database flags*, check the value of *log_hostname* flag is set to appropriately.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list


  2. Use the below command for every Cloud SQL PostgreSQL database instance to verify the value of *log_hostname*

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_hostname")|.value'`,
  rationale: `Logging hostnames can incur overhead on server performance as for each statement logged, DNS resolution will be required to convert IP address to hostname. Depending on the setup, this may be non-negligible. Additionally, the IP addresses that are logged can be resolved to their DNS names later when reviewing the logs excluding the cases where dynamic hostnames are used. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_hostname* from the drop-down menu and set appropriate value.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.

  **Using Command Line:**

  1. List all Cloud SQL database Instances

          gcloud sql instances list

  2. Configure the *log_hostname* database flag for every Cloud SQL PosgreSQL database instance using the below command.

          gcloud sql instances patch INSTANCE_NAME --database-flags log_hostname=<off|on>

  **Note:** This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT`,
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
              equal: 'log_hostname',
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
