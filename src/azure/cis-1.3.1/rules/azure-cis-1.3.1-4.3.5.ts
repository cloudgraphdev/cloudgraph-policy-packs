export default {
  id: 'azure-cis-1.3.1-4.3.5',
  title: 'Azure CIS 4.3.5 Ensure server parameter \'log_disconnections\' is set to \'ON\' for PostgreSQL Database Server',

  description: 'Enable log_disconnections on PostgreSQL Servers.',

  audit: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_disconnections.
  5. Ensure that value is set to ON.

  **Using Azure Command Line Interface 2.0**

  Ensure log_connections value is set to ON
      az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections`,

  rationale: 'Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.',

  remediation: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_disconnections.
  5. Click ON and save.

  **Using Azure Command Line Interface 2.0**

  Use the below command to update log_disconnections configuration.
        az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections --value on`,

  references: [
      'https://docs.microsoft.com/en-us/rest/api/postgresql/configurations/listbyserver',
      'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  severity: 'high',
  gql: `{
    queryazurePostgreSqlServer{
      __typename
      configurations{
        name
        value
      }
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  conditions: {
    path: '@.configurations',
    array_any:{
      path: '[*]',
      and: [
        {
          path: '[*].name',
          equal: 'log_disconnections',
        },
        {
          path: '[*].value',
          equal: 'on',
        },
      ],
    }
  },
}
