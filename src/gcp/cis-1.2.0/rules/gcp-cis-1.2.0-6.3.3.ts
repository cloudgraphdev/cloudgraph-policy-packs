export default {
  id: 'gcp-cis-1.2.0-6.3.3',
  description:
    "GCP CIS 6.3.3 Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate",
  audit: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag *user connections* that has been set is listed under the *Database flags* section.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  
  2. Ensure the below command returns value, which is according to your organization recommended value, for every Cloud SQL SQL Server database instance.
  
          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="user connections")|.value'`,
  rationale: `The *user connections* option specifies the maximum number of simultaneous user connections that are allowed on an instance of SQL Server. The actual number of user connections allowed also depends on the version of SQL Server that you are using, and also the limits of your application or applications and hardware. SQL Server allows a maximum of 32,767 user connections. Because user connections is a dynamic (self-configuring) option, SQL Server adjusts the maximum number of user connections automatically as needed, up to the maximum value allowable. For example, if only 10 users are logged in, 10 user connection objects are allocated. In most cases, you do not have to change the value for this option. The default is 0, which means that the maximum (32,767) user connections are allowed. This recommendation is applicable to SQL Server database instances.`,
  remediation: `**Using Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the SQL Server instance for which you want to enable to database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *user connections* from the drop-down menu, and set its value to your organization recommended value.
  6. Click *Save* to save your changes.
  7. Confirm your changes under *Flags* on the Overview page.
  
  **Using Command Line:**
  
  1. List all Cloud SQL database Instances
  
          gcloud sql instances list
  
  2. Configure the *user connections* database flag for every Cloud SQL SQL Server database instance using the below command.
  
          gcloud sql instances patch INSTANCE_NAME --database-flags "user connections=[0-32,767]"
  
  **Note:**
  
  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags you want set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/sqlserver/flags`,
    `https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-user-connections-server-configuration-option?view=sql-server-ver15`,
    `https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018- 03-09/finding/V- 79119`,
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
  severity: 'unknown',
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
                    equal: 'user connections',
                  },
                  {
                    path: '[*].value',
                    notIn: [null, ''],
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
