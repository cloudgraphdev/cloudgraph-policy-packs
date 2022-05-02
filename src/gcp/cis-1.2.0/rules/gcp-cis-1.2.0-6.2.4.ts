export default {
  id: 'gcp-cis-1.2.0-6.2.4',
  title:
    "GCP CIS 6.2.4 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
  description: `Enabling the log_disconnections setting logs the end of each session, including the
  session duration.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to the *Configuration* card.
  4. Under *Database flags*, check the value of *log_disconnections* flag is configured as expected.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list

  2. Ensure the below command returns on for every Cloud SQL PostgreSQL database instance:

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_disconnections")|.value'`,
  rationale: `PostgreSQL does not log session details such as duration and session end by default. Enabling the *log_disconnections* setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period. The *log_disconnections* and *log_connections* work hand in hand and generally, the pair would be enabled/disabled together. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_disconnections* from the drop-down menu and set the value as *on*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list

  2. Configure the *log_disconnections* database flag for every Cloud SQL PosgreSQL database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags log_disconnections=on

  **Note:**

  This command will overwrite all previously setdatabase flags. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT`,
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
                    equal: 'log_disconnections',
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
