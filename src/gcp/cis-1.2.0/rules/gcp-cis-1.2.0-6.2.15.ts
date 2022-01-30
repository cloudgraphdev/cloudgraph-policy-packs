export default {
  id: 'gcp-cis-1.2.0-6.2.15',
  description:
    "GCP CIS 6.2.15 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)",
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to the *Configuration* card.
  4. Under *Database flags*, check that the value of *log_temp_files* flag is set to *0*.
  
  **From Command Line:**
  
  1. List all Cloud SQL database Instances using the following command:
  
          gcloud sql instances list
  
  2. Ensure that the below command returns *0* for every Cloud SQL PostgreSQL database instance
  
          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_temp_files")|.value'`,
  rationale: `If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be due to either poor application coding or deliberate resource starvation attempts.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_temp_files* from the drop-down menu and set the value as *0*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.
  
  **From Command Line:**
  
  1. List all Cloud SQL database instances using the following command:
  
          gcloud sql instances list
  
  2. Configure the *log_temp_files* database flag for every Cloud SQL PosgreSQL database instance using the below command.
  
          gcloud sql instances patch INSTANCE_NAME --database-flags log_temp_files='0'
  
  **Note:**
  
  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#GUC-LOG-TEMP-FILES`,
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
                    equal: 'log_temp_files',
                  },
                  {
                    path: '[*].value',
                    equal: '0',
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
