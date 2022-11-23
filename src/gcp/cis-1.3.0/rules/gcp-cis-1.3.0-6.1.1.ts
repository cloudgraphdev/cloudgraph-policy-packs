/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.3.0-6.1.1',
  title:
    'GCP CIS 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges',
  description: `It is recommended to set a password for the administrative user (root by default) to
  prevent unauthorized access to the SQL database instances.

  This recommendation is applicable only for MySQL Instances. PostgreSQL does not offer any setting for No Password from the cloud console.`,
  audit: `**From Command Line:**

  1. List All SQL database instances of type MySQL.

  gcloud sql instances list --filter='DATABASE_VERSION:MYSQL*'

  2. For every MySQL instance try to connect from an authorized network:

          mysql -u root -h <Instance_IP>

  The command should return either an error message or a password prompt.
  Sample Error message:

      ERROR 1045 (28000): Access denied for user 'root'@'[Inatance_IP]' (using password: NO)

  If a command produces the mysql prompt, the SQL instance allows anyone to connect with
  administrative privileges without needing a password.


  **Note:** The No Password setting is exposed only at the time of MySQL instance creation.
  Once the instance is created, the Google Cloud Platform Console does not expose the set to
  confirm whether a password for an administrative user is set to a MySQL instance.`,
  rationale: `At the time of MySQL Instance creation, not providing an administrative password allows
  anyone to connect to the SQL database instance with administrative privileges. The root
  password should be set to ensure only authorized users have these privileges.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Platform Console using
      https://console.cloud.google.com/sql/
  2. Select the instance to open its Overview page.
  3. Select Access Control > Users.
  4. Click the more actions icon for the user to be updated.
  5. Select Change password, specify a new password, and click OK.

  **From Command Line:**
  Set a password to a MySql instance:

      gcloud sql users set-password [USER_NAME] [HOST] --instance=[INSTANCE_NAME] --password=[PASSWORD]

  **Default Value:**

  From the Google Cloud Platform Console, the Create Instance workflow enforces the rule
  to enter the root password unless the option No Password is selected explicitly.`,
  references: [
    'https://cloud.google.com/sql/docs/mysql/create-manage-users',
    'https://cloud.google.com/sql/docs/mysql/create-instance',
  ],
  severity: 'high',
}
