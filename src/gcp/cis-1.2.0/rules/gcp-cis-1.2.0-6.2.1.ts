export default {
  id: 'gcp-cis-1.2.0-6.2.1',
  title:
    "GCP CIS 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
  description: `Ensure that the log_checkpoints database flag for the Cloud SQL PostgreSQL instance is
  set to on.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page.
  3. Ensure that the database flag *log_checkpoints* that has been set is listed under the *Database flags* section.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Ensure that the below command returns on for every Cloud SQL PostgreSQL
      database instance.

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_checkpoints")|.value'`,
  rationale: `Enabling *log_checkpoints* causes checkpoints and restart points to be logged in the server log. Some statistics are included in the log messages, including the number of buffers written and the time spent writing them. This parameter can only be set in the postgresql.conf file or on the server command line. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_checkpoints* from the drop-down menu, and set its value.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Configure the *log_checkpoints* database flag for every Cloud SQL PosgreSQL database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags log_checkpoints=on

  **Note:**

  This command will overwrite all previously set database flags. To keep those and add new ones, include the values for all flags to be set on the instance. Any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT`,
    `https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag`,
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
                    equal: 'log_checkpoints',
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
      },
    ],
  },
}
