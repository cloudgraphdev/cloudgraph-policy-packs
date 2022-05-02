export default {
  id: 'azure-cis-1.3.1-4.3.4',  
  title: 'Azure CIS 4.3.4 Ensure server parameter \'log_connections\' is set to \'ON\' for PostgreSQL Database Server',
  
  description: 'Enable log_connections on PostgreSQL Servers.',
  
  audit: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_connections.
  5. Ensure that value is set to ON.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure log_connections value is set to ON

    az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_connections`,
  
  rationale: `Enabling log_connections helps PostgreSQL Database to log attempted connection to the
  server, as well as successful completion of client authentication. Log data can be used to
  identify, troubleshoot, and repair configuration errors and suboptimal performance.`,
  
  remediation: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_connections.
  5. Click ON and save.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to update log_connections configuration.
  
    az postgres server configuration set --resource-group <resourceGroupName>
    --server-name <serverName> --name log_connections --value on`,
  
  references: [
    'https://docs.microsoft.com/en-us/rest/api/postgresql/configurations/listbyserver',
    'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  gql: `{
    queryazurePostgreSqlServer {
      id
      __typename
      configurations {
        name
        value
      }
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  severity: 'high',
  conditions: {
    path: '@.configurations',
    array_any: {
      and: [
        {      
          path: '[*].name',
          equal: 'log_connections',
        },
        {
          path: '[*].value',
          equal: 'on',
        }
      ],
    }
  },
}
