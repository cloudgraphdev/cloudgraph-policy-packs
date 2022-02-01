export default {
  id: 'gcp-cis-1.2.0-6.2.3',
  description:
    "GCP CIS 6.2.3 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page.
  3. Go to the *Configuration* card.
  4. Under *Database flags*, check the value of *log_connections* flag to determine if it is configured as expected.
  
  **From Command Line:**
  
  1. List all Cloud SQL database instances using the following command:
  
          gcloud sql instances list
  
  2. Ensure the below command returns *on* for every Cloud SQL PostgreSQL database instance:
  
          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_connections")|.value'
  `,
  rationale: `PostgreSQL does not log attempted connections by default. Enabling the *log_connections* setting will create log entries for each attempted connection as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_connections* from the drop-down menu and set the value as *on*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.
  
  **From Command Line:**
  
  1. List all Cloud SQL database instances using the following command:
  
          gcloud sql instances list
  
  2. Configure the *log_connections* database flag for every Cloud SQL PosgreSQL database instance using the below command.
  
          gcloud sql instances patch INSTANCE_NAME --database-flags log_connections=on
  
  **Note:**
  
  This command will overwrite all previously set database flags. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
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
                    equal: 'log_connections',
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
