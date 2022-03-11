export default {
  id: 'azure-cis-1.3.1-8.2',  
  title: 'Azure CIS 8.2 Ensure that the expiration date is set on all Secrets',
  
  description: 'Ensure that all Secrets in the Azure Key Vault have an expiration time set.',
  
  audit: `**From Azure Console**
  
  1. Go to Key vaults
  2. For each Key vault, click on Secrets.
  3. Under the Settings section, Make sure Enabled? is set to Yes
  4. Ensure that each secret in the vault has EXPIRATION DATE set as appropriate
  
  **Using Azure Command Line Interface 2.0**  
  Ensure that the output of the below command contains ID (id), enabled status as true and Expiration date (expires) is not empty or null:
  
      az keyvault secret list --vault-name <KEYVAULTNAME> --query [*].[{"id":id},{"enabled":attributes.enabled},{"expires":attributes.expires}]`,
  
  rationale: 'The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration time) attribute identifies the expiration time on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration time for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.',
  
  remediation: `**From Azure Console**
  
  1. Go to Key vaults
  2. For each Key vault, click on Secrets.
  3. Under the Settings section, Make sure Enabled? is set to Yes
  4. Set an appropriate EXPIRATION DATE on all secrets.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to set EXPIRATION DATE on the all secrets.
  
      az keyvault secret set-attributes --name <secretName> --vault-name <vaultName> --expires Y-m-d'T'H:M:S'Z'`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis',
      'https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-secrets',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-4-set-up-emergency-access-in-azure-ad',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-8-choose-approval-process-for-microsoft-support',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  gql: `{
    queryazureKeyVault {
      id
      __typename
      secrets {
        properties {
          attributes {
            enabled
            expires
          }
        }
      }
    }
  }`,
  resource: 'queryazureKeyVault[*]',
  severity: 'high',
  conditions: {
    path: '@secrets',
    array_all: {
      and: [
        {
          path: '[*].properties.attributes.enabled',
          equal: true,
        },
        {
          path: '[*].properties.attributes.expires',
          notIn: [null, ''],
        },
      ],
    },
  },
}
