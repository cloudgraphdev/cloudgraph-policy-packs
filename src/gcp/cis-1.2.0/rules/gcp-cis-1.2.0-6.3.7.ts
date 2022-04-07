export default {
  id: 'gcp-cis-1.2.0-6.3.7',
  title:
    "GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'",
  description: `It is recommended to set contained database authentication database flag for Cloud
  SQL on the SQL Server instance is set to off.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag c*ontained database authentication* that has been set is listed under the *Database flags* section.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Ensure the below command returns *off* for every Cloud SQL SQL Server database instance.

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="contained database authentication")|.value'`,
  rationale: `A contained database includes all database settings and metadata required to define the database and has no configuration dependencies on the instance of the Database Engine where the database is installed. Users can connect to the database without authenticating a login at the Database Engine level. Isolating the database from the Database Engine makes it possible to easily move the database to another instance of SQL Server. Contained databases have some unique threats that should be understood and mitigated by SQL Server Database Engine administrators. Most of the threats are related to the USER WITH PASSWORD authentication process, which moves the authentication boundary from the Database Engine level to the database level, hence this is recommended to disable this flag. This recommendation is applicable to SQL Server database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the SQL Server instance for which you want to enable to database flag.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *contained database authentication* from the drop-down menu, and set its value to *off*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list

  2. Configure the *contained database authentication* database flag for every Cloud SQL SQL Server database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags "contained database authentication=off"

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, , include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/sqlserver/flags`,
    `https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15`,
    `https://docs.microsoft.com/en-us/sql/relational-databases/databases/security-best-practices-with-contained-databases?view=sql-server-ver15`,
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
  severity: 'high',
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
                    equal: 'contained database authentication',
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
