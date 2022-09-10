// similar to CIS 4.3.2
export default {
  id: 'pci-dss-3.2.1-encryption-check-2',  
  title: 'Encryption Check 2: MySQL Database server \'enforce SSL connection\' should be enabled',
  
  description: 'Enable SSL connection on MYSQL Servers.',
  
  audit: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure- list text here.com
  2. Go to Azure Database for MySQL server
  3. For each database, click on Connection security
  4. In SSL settings
  5. Ensure Enforce SSL connection is set to ENABLED.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command returns ENABLED.
  
    az mysql server show --resource-group myresourcegroup --name <resourceGroupName> --query sslEnforcement`,
  
  rationale: `SSL connectivity helps to provide a new layer of security, by connecting database server to
  client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between
  database server and client applications helps protect against "man in the middle" attacks
  by encrypting the data stream between the server and application.`,
  
  remediation: `**From Azure Console:**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for MySQL server
  3. For each database, click on Connection security
  4. In SSL settings
  5. Click on ENABLED for Enforce SSL connection
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to set MYSQL Databases to Enforce SSL connection.
  
    az mysql server update --resource-group <resourceGroupName> --name <serverName> --ssl-enforcement Enabled`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security',
    'https://docs.microsoft.com/en-us/azure/mysql/howto-configure-ssl',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
  ],  
  gql: `{
    queryazureMySqlServer {
      id
      __typename       
      sslEnforcement
    }
  }`,
  resource: 'queryazureMySqlServer[*]',
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