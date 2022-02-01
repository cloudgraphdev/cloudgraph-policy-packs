export default {
  id: 'gcp-cis-1.2.0-6.2.14',
  description:
    "GCP CIS 6.2.14 Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter",
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Go to *Configuration* card
  4. Under *Database flags*, check the value of *log_min_error_statement* flag is configured as to *ERROR* or stricter.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  
  2. Use the below command for every Cloud SQL PostgreSQL database instance to verify the value of *log_min_error_statement* is set to *ERROR* or stricter.
  
          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_min_error_statement")|.value'`,
  rationale: `Auditing helps in troubleshooting operational problems and also permits forensic analysis. If *log_min_error_statement* is not set to the correct value, messages may not be classified as error messages appropriately. Considering general log messages as error messages would make is difficult to find actual errors and considering only stricter severity levels as error messages may skip actual errors to log their SQL statements. The *log_min_error_statement* flag should be set to *ERROR* or stricter. This recommendation is applicable to PostgreSQL database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance for which you want to enable the database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_min_error_statement* from the drop-down menu and set appropriate value.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  2. Configure the *log_min_error_statement* database flag for every Cloud SQL PosgreSQL database instance using the below command.
  
          gcloud sql instances patch INSTANCE_NAME --database-flags log_min_error_statement=<DEBUG5|DEBUG4|DEBUG3|DEBUG2|DEBUG1|INFO|NOTICE|WARNING|ERROR>
  
  **Note:**
  
  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/postgres/flags`,
    `https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHEN`,
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
                    equal: 'log_min_error_statement',
                  },
                  {
                    path: '[*].value',
                    in: ['error', 'log', 'fatal', 'panic'],
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
