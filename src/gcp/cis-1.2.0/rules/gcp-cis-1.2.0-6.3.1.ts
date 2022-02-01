export default {
  id: 'gcp-cis-1.2.0-6.3.1',
  description:
    "GCP CIS 6.3.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'",
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag *external scripts enabled* that has been set is listed under the *Database flags* section.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  2. Ensure the below command returns *off* for every Cloud SQL SQL Server database instance
  
          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="external scripts enabled")|.value'`,
  rationale: `*external scripts enabled* enable the execution of scripts with certain remote language extensions. This property is OFF by default. When Advanced Analytics Services is installed, setup can optionally set this property to true. As the External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed, which could adversely affect the security of the system, hence this should be disabled.This recommendation is applicable to SQL Server database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the SQL Server instance for which you want to enable to database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *external scripts enabled* from the drop-down menu, and set its value to *off*.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  2. Configure the *external scripts enabled* database flag for every Cloud SQL SQL Server database instance using the below command.
  
          gcloud sql instances patch INSTANCE_NAME --database-flags "external scripts enabled=off"
  
  **Note:**
  
  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/external-scripts-enabled-server-configuration-option?view=sql-server-ver15`,
    `https://cloud.google.com/sql/docs/sqlserver/flags`,
    `https://docs.microsoft.com/en-us/sql/advanced-analytics/concepts/security?view=sql-server-ver15`,
    `https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018-03-09/finding/V-79347`
  ],
  gql: `{
    querygcpProject{
      id
      projectId
      __typename
      sqlInstances(filter:{ databaseVersion: {regexp:  "/SQLSERVER*/"}}){
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
  severity: 'low',
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
                    equal: 'external scripts enabled',
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
