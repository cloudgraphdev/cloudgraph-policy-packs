export default {
  id: 'azure-cis-1.3.1-8.4',  
  title: 'Azure CIS 8.4 Ensure the key vault is recoverable',
  
  description: `The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects.
  
  It is recommended the key vault be made recoverable by enabling the "Do Not Purge" and "Soft Delete" functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.`,
  
  audit: `**From Azure Portal**  
  Azure Portal does not have provision to update the respective configurations  
  
  **Using Azure CLI 2.0**
  
  1. List all Resources of type Key Vaults:
  
          az resource list --query "[?type=='Microsoft.KeyVault/vaults']"
  
  2. For Every Key Vault ID ensure check parameters enableSoftDelete and enablePurgeProtection are set to enabled.
  
          az resource show --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault /vaults/<keyVaultName>`,
  
  rationale: `There could be scenarios where users accidently run delete/purge commands on key vault or attacker/malicious user does it deliberately to cause disruption. Deleting or purging a key vault leads to immediate data loss as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There are 2 key vault properties that plays role in permanent unavailability of a key vault.
  
  1. enableSoftDelete:
  
  Setting this parameter to true for a key vault ensures that even if key vault is deleted, Key vault itself or its objects remain recoverable for next 90days. In this span of 90 days either key vault/objects can be recovered or purged (permanent deletion). If no action is taken, after 90 days key vault and its objects will be purged.
  
  2. enablePurgeProtection:
  
  enableSoftDelete only ensures that key vault is not deleted permanently and will be recoverable for 90 days from date of deletion. However, there are chances that the key vault and/or its objects are accidentally purged and hence will not be recoverable. Setting enablePurgeProtection to "true" ensures that the key vault and its objects cannot be purged.
  
  Enabling both the parameters on key vaults ensures that key vaults and their objects cannot be deleted/purged permanently.`,
  
  remediation: `To enable "Do Not Purge" and "Soft Delete" for a Key Vault:  
  **From Azure Portal**  
  Azure Portal does not have provision to update the respective configurations
  
  **Using Azure CLI 2.0**
  
      az resource update --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault /vaults/<keyVaultName> --set properties.enablePurgeProtection=true properties.enableSoftDelete=true`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-soft-delete-cli',
      'https://blogs.technet.microsoft.com/kv/2017/05/10/azure-key-vault-recovery-options/',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-8-define-backup-and-recovery-strategy',
  ],  
  gql: `{
    queryazureKeyVault {
      id
      __typename
      enableSoftDelete
      enablePurgeProtection
    }
  }`,
  resource: 'queryazureKeyVault[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.enableSoftDelete',
        equal: true,
      },
      {
        path: '@.enablePurgeProtection',
        equal: true,
      },
    ],
  },
}
