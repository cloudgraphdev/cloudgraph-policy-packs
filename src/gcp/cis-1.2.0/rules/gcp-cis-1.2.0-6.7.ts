export default {
  id: 'gcp-cis-1.2.0-6.7',
  title:
    'GCP CIS 6.7 Ensure that Cloud SQL database instances are configured with automated backups',
  description:
    'It is recommended to have all SQL database instances set to enable automated backups.',
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Click the instance name to open its instance details page.
  3. Go to the *Backups* menu.
  4. Ensure that *Automated backups* is set to *Enabled* and *Backup time* is mentioned.

  **From Command Line:**

  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Ensure that the below command returns *True* for every Cloud SQL database instance.

          gcloud sql instances describe INSTANCE_NAME --format="value('Enabled':settings.backupConfiguration.enabled)"`,
  rationale: `Backups provide a way to restore a Cloud SQL instance to recover lost data or recover from a problem with that instance. Automated backups need to be set for any instance that contains data that should be protected from loss or damage. This recommendation is applicable for SQL Server, PostgreSql, MySql generation 1 and MySql generation 2 instances.`,
  remediation: `**From Console:**
  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Select the instance where the backups need to be configured.
  3. Click *Edit*.
  4. In the *Backups* section, check 'Enable automated backups', and choose a backup window.
  5. Click *Save*.

  **From Command Line:**
  1. List all Cloud SQL database instances using the following command:

          gcloud sql instances list

  2. Enable *Automated backups* for every Cloud SQL database instance using the below command:

          gcloud sql instances patch INSTANCE_NAME --backup-start-time [HH:MM]

  The *backup-start-time* parameter is specified in 24-hour time, in the UTC±00 time zone, and specifies the start of a 4-hour backup window. Backups can start any time during the backup window.`,
  references: [
    `https://cloud.google.com/sql/docs/mysql/backup-recovery/backups`,
    `https://cloud.google.com/sql/docs/postgres/backup-recovery/backing-up`,
  ],
  gql: `{
    querygcpSqlInstance{
      id
      __typename
      name
      settings {
        backupConfiguration {
          enabled
          startTime
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.settings.backupConfiguration.enabled',
        equal: true,
      },
      {
        path: '@.settings.backupConfiguration.startTime',
        notIn: [null, false],
      },
    ],
  },
}
