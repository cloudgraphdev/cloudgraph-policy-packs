export default {
  id: 'azure-nist-800-53-rev4-7.1',  
  title: 'Azure NIST 7.1 PostgreSQL Database configuration "connection_throttling" should be on',
  
  description: 'Enabling _connection_throttling_ helps the PostgreSQL Database to _Set the verbosity of logged messages_ which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  - Navigate to [Azure Database for PostgreSQL servers](https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforPostgreSQL%2Fservers).
  - Select the PostgreSQL server.
  - In the left navigation, select Server parameters.
  - In _connection_throttling_, select ON.
  - Click Save.
  
  **Using Command Line:**
  
  - To enable _connection_throttling_:
  
          az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name connection_throttling --value on`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/postgresql/concepts-monitoring',
      'https://docs.microsoft.com/en-us/cli/azure/postgres/server/configuration?view=azure-cli-latest#az-postgres-server-configuration-set',
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
  severity: 'medium',
  conditions: {
    path: '@.configurations',
    array_any: {
      and: [
        {
          path: '[*].name', 
          equal: 'connection_throttling' 
        },
        {
          path: '[*].value', 
          equal: 'on' 
        },
      ],
    },
  },
}
