export default {
  id: 'azure-cis-1.3.1-4.3.6',
  title: 'Azure CIS 4.3.6 Ensure server parameter \'connection_throttling\' is set to \'ON\' for PostgreSQL Database Server',

  description: 'Enable connection_throttling on PostgreSQL Servers.',

  audit: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for connection_throttling.
  5. Ensure that value is set to ON.

  **Using Azure Command Line Interface 2.0**

  Ensure connection_throttling value is set to ON

      az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name connection_throttling`,

  rationale: 'Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.',

  remediation: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for connection_throttling.
  5. Click ON and save.

  **Using Azure Command Line Interface 2.0**

  Use the below command to update connection_throttling configuration.

      az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name connection_throttling --value on`,

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
          equal: 'connection_throttling',
        },
        {
          path: '[*].value',
          equal: 'on',
        },
      ],
    }
  },
}
