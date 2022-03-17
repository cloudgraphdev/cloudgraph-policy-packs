export default {
  id: 'azure-cis-1.3.1-4.3.3',  
  title: 'Azure CIS 4.3.3 Ensure server parameter \'log_checkpoints\' is set to \'ON\' for PostgreSQL Database Server',
  
  description: 'Enable log_checkpoints on PostgreSQL Servers.',
  
  audit: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_checkpoints.
  5. Ensure that value is set to ON.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure value is set to ON

    az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_checkpoints`,
  
  rationale: `Enabling log_checkpoints helps the PostgreSQL Database to Log each checkpoint in turn
  generates query and error logs. However, access to transaction logs is not supported. Query
  and error logs can be used to identify, troubleshoot, and repair configuration errors and
  sub-optimal performance.`,
  
  remediation: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_checkpoints.
  5. Click ON and save.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to update log_checkpoints configuration.
  
    az postgres server configuration set --resource-group <resourceGroupName>
    --server-name <serverName> --name log_checkpoints --value on`,
  
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
          equal: 'log_checkpoints',
        },
        {
          path: '[*].value',
          equal: 'on',
        }
      ],
    }
  },
}
