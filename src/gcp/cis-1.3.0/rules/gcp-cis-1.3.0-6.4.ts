export default {
  id: 'gcp-cis-1.3.0-6.4',
  title:
    'GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL',
  description:
    'It is recommended to enforce all incoming connections to SQL database instance to use SSL.',
  audit: `**From Console:**

  1. Go to https://console.cloud.google.com/sql/instances.
  2. Click on an instance name to see its configuration overview.
  3. In the left-side panel, select *Connections*.
  4. In the *SSL connections* section, ensure that *Only secured connections are allowed to connect to this instance*.

  **From Command Line:**

  1. List all SQL database instances using the following command:

          gcloud sql instances list

  2. Get the detailed configuration for every SQL database instance using the following
      command:

          gcloud sql instances describe INSTANCE_NAME

  Ensure that section *settings: ipConfiguration* has the parameter *requireSsl* set to *true*.`,
  rationale: 'SQL database connections if successfully trapped (MITM); can reveal sensitive data like credentials, database queries, query outputs etc. For security, it is recommended to always use SSL encryption when connecting to your instance. This recommendation is applicable for Postgresql, MySql generation 1, MySql generation 2 and SQL Server 2017 instances.',
  remediation: `**From Console:**

  1. Go to https://console.cloud.google.com/sql/instances.
  2. Click on an instance name to see its configuration overview.
  3. In the left-side panel, select *Connections*.
  4. In the *SSL connections* section, click *Allow only SSL connections*.
  5. Under *Configure SSL server certificates* click *Create new certificate*.
  6. Under *Configure SSL client certificates* click *Create a client certificate*.
  7. Follow the instructions shown to learn how to connect to your instance.

  **From Command Line:**

  To enforce SSL encryption for an instance run the command:

          gcloud sql instances patch INSTANCE_NAME --require-ssl

  **Note:**

  *RESTART* is required for type MySQL Generation 1 Instances (*backendType: FIRST_GEN*) to get this configuration in effect.`,
  references: [
    'https://cloud.google.com/sql/docs/postgres/configure-ssl-instance',
  ],
  gql: `{
    querygcpSqlInstance {
      id
      __typename
      name
      settings {
        ipConfiguration {
          requireSsl
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.settings.ipConfiguration.requireSsl',
    equal: true,
  },
}
