export default {
  id: 'azure-cis-1.3.1-4.3.1',  
  title: 'Azure CIS 4.3.1 Ensure \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server',
  
  description: `Enable SSL connection on PostgreSQL Servers.`,
  
  audit: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Connection security
  4. In SSL settings
  5. Ensure Enforce SSL connection is set to ENABLED.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command returns ENABLED.
  
    az postgres server show --resource-group myresourcegroup --name <resourceGroupName> --query sslEnforcement`,
  
  rationale: `SSL connectivity helps to provide a new layer of security, by connecting database server
  to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between
  database server and client applications helps protect against "man in the middle" attacks
  by encrypting the data stream between the server and application.`,
  
  remediation: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Connection security
  4. In SSL settings.
  5. Click on ENABLED to Enforce SSL connection
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to enforce ssl connection for PostgreSQL Database.
  
    az postgres server update --resource-group <resourceGroupName> --name <serverName> --ssl-enforcement Enabled`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
  ],  
  gql: `{
    queryazurePostgreSqlServer {
      id
      __typename       
      sslEnforcement
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.sslEnforcement',
        equal: 'Enabled',
      },
    ],
  },
}