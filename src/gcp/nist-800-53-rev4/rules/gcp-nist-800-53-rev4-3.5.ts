// GCP CIS 1.2.0 Rule equivalent 6.2.6
export default {
  id: 'gcp-nist-800-53-rev4-3.5',
  title:
    "GCP NIST 3.5 PostgreSQL database instance 'log_lock_waits' database flag should be set to 'on'",
  description: `Enabling the log_lock_waits flag for a PostgreSQL instance creates a log for any session
  waits that take longer than the alloted deadlock_timeout time to acquire a lock.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance to open its Instance Overview page.
  3. Go to the *Configuration* card.
  4. Under *Database flags*, check if the value of the *log_lock_waits* flag is configured as expected.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list

  2. Ensure the below command returns *on* for every Cloud SQL PostgreSQL database instance

          gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="log_lock_waits")|.value'`,
  rationale: 'The deadlock timeout defines the time to wait on a lock before checking for any conditions. Frequent run overs on deadlock timeout can be an indication of an underlying issue. Logging such waits on locks by enabling the *log_lock_waits* flag can be used to identify poor performance due to locking delays or if a specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time. This recommendation is applicable to PostgreSQL database instances.',
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the PostgreSQL instance where the database flag needs to be enabled.
  3. Click *Edit*.
  4. Scroll down to the *Flags* section.
  5. To set a flag that has not been set on the instance before, click *Add item*, choose the flag *log_lock_waits* from the drop-down menu and set the value as *on*.
  6. Click *Save*.
  7. Confirm the changes under *Flags* on the Overview page.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Configure the *log_lock_waits* database flag for every Cloud SQL PosgreSQL database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --database-flags log_lock_waits=on

  **Note:**

  This command will overwrite all database flags previously set. To keep those and add new ones, include the values for all flags to be set on the instance; any flag not specifically included is set to its default value. For flags that do not take a value, specify the flag name followed by an equals sign ("=").`,
  references: [
    'https://cloud.google.com/sql/docs/postgres/flags',
    'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT',
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
                    equal: 'log_lock_waits',
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
