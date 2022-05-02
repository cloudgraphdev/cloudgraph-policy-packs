export default {
  id: 'azure-cis-1.3.1-4.5',  
  title: 'Azure CIS 4.5 Ensure SQL server\'s TDE protector is encrypted with Customer-managed key',
  
  description: `TDE with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service, and promotion of separation of duties.
  
  With TDE, data is encrypted at rest with a symmetric key (called the database encryption key) stored in the database or data warehouse distribution. To protect this data encryption key (DEK) in the past, only a certificate that the Azure SQL Service managed could be used. Now, with Customer-managed key support for TDE, the DEK can be protected with an asymmetric key that is stored in the Key Vault. Key Vault is a highly available and scalable cloud-based key store which offers central key management, leverages FIPS 140-2 Level 2 validated hardware security modules (HSMs), and allows separation of management of keys and data, for additional security.
  
  Based on business needs or criticality of data/databases hosted a SQL server, it is recommended that the TDE protector is encrypted by a key that is managed by the data owner (Customer-managed key).`,
  
  audit: `**From Azure Portal:**
  
  1. Go to SQL servers
  2. For the desired server instance
  3. Click On Transparent data encryption
  4. Ensure that Use your own key is set to YES
  5. Ensure Make selected key the default TDE protector is checked
  
  **Using Azure CLI:**
  
      az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" GET https://management.azure.com/subscriptions/$0/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/encryptionProtector?api-version=2015-05-01-preview'
  
  Ensure the output of the command contains properties  
  kind set to azurekeyvault  
  serverKeyType set to AzureKeyVault  
  uri is not null`,
  
  rationale: 'Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.',
  
  remediation: `**From Azure Console:**  
  Go to SQL servers  
  For the desired server instance
  
  1. Click On Transparent data encryption
  2. Set Use your own key to YES
  3. Browse through your key vaults to Select an existing key or create a new key in Key Vault.
  4. Check Make selected key the default TDE protector
  
  **Using Azure CLI:**  
  Use the below command to encrypt SQL server's TDE protector with a Customer-managed key
  
      az sql server tde-key >> Set --resource-group <resourceName> --server <dbServerName> --server-key-type {AzureKeyVault} [--kid <keyIdentifier>]`,
  
  references: [
      'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption-byok-azure-sql',
      'https://azure.microsoft.com/en-in/blog/preview-sql-transparent-data-encryption-tde-with-bring-your-own-key-support/',
      'https://winterdom.com/2017/09/07/azure-sql-tde-protector-keyvault',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-1-standardize-azure-active-directory-as-the-central-identity-and-authentication-system',
  ],  
  gql: `{
    queryazureSqlServer {
      id
      __typename
      encryptionProtectors {
        kind
        serverKeyType
        uri
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    path: '@.encryptionProtectors',
    array_any: {
      and: [
        {
          path: '[*].kind',
          equal: 'azurekeyvault',
        },
        {
          path: '[*].serverKeyType',
          equal: 'AzureKeyVault',
        },
        {
          path: '[*].uri',
          notIn: [null, ''],
        },
      ],
    },
  },
}
