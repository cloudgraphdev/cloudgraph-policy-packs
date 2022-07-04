export default {
  id: 'gcp-cis-1.2.0-6.1.3',
  title:
    "GCP CIS 6.1.3 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'",
  description: `It is recommended to set the local_infile database flag for a Cloud SQL MySQL instance
  to off.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its *Instance Overview* page
  3. Ensure the database flag *local_infile* that has been set is listed under the *Database flags* section.

  **From Command Line:**

  1. List all Cloud SQL database instances:

          gcloud sql instances list

  2. Ensure the below command returns *off* for every Cloud SQL MySQL database instance.

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="local_infile")|.value'
  `,
  rationale: `The *local_infile* flag controls the server-side LOCAL capability for LOAD DATA statements. Depending on the *local_infile* setting, the server refuses or permits local data loading by clients that have LOCAL enabled on the client side.

  To explicitly cause the server to refuse LOAD DATA LOCAL statements (regardless of how client programs and libraries are configured at build time or runtime), start mysqld with local_infile disabled. local_infile can also be set at runtime.

  Due to security issues associated with the *local_infile* flag, it is recommended to disable it. This recommendation is applicable to MySQL database instances.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the MySQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *local_infile* from the drop-down menu, and set its value to *off*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Configure the *local_infile* database flag for every Cloud SQL Mysql database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags local_infile=off

  **Note:**

  This command will overwrite all database flags that were previously set. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    `https://cloud.google.com/sql/docs/mysql/flags`,
    `https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_local_infile`,
    `https://dev.mysql.com/doc/refman/5.7/en/load-data-local.html`,
  ],
  gql: `{
     querygcpSqlInstance(filter:{ databaseVersion: {regexp:  "/MYSQL*/"}}){
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
  exclude: { not: { path: '@.databaseVersion', match: /MYSQL*/ } },
  severity: 'unknown',
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
              equal: 'local_infile',
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
}
