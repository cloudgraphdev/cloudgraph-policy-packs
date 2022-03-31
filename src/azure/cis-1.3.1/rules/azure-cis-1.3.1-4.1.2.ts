export default {
  id: 'azure-cis-1.3.1-4.1.2',  
  title: 'Azure CIS 4.1.2 Ensure that \'Data encryption\' is set to \'On\' on a SQL Database',
  
  description: `Enable Transparent Data Encryption on every SQL server.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL databases
  2. For each DB instance
  3. Click on Transparent data encryption
  4. Ensure that Data encryption is set to On
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is Enabled
  
    az sql db tde show --resource-group <resourceGroup> --server <dbServerName> --database <dbName> --query status`,
  
  rationale: `Azure SQL Database transparent data encryption helps protect against the threat of
  malicious activity by performing real-time encryption and decryption of the database,
  associated backups, and transaction log files at rest without requiring changes to the
  application.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL databases
  2. For each DB instance
  3. Click on Transparent data encryption
  4. Set Data encryption to On
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to enable Transparent data encryption for SQL DB instance.
  
    az sql db tde set --resource-group <resourceGroup> --server <dbServerName> --database <dbName> --status Enabled
    
  Note:
  - TDE cannot be used to encrypt the logical master database in SQL Database. The
  master database contains objects that are needed to perform the TDE operations on
  the user databases.
  - Azure Portal does not show master databases per SQL server. However, CLI/API
  responses will show master databases.`,
  
  references: [
    'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption-with-azure-sql-database',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-5-encrypt-sensitive-data-at-rest',
  ],  
  gql: `{
    queryazureDatabaseSql {
      id
      __typename       
      transparentDataEncryptions {
        state
      }
    }
  }`,
  resource: 'queryazureDatabaseSql[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.transparentDataEncryptions',
        isEmpty: false,
      },
      {
        path: '@.transparentDataEncryptions',
        array_any: {
          path: '[*].state',
          equal: 'Enabled',
        }
      },
    ],
  },
}