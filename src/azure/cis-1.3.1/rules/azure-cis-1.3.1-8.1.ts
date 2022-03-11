export default {
  id: 'azure-cis-1.3.1-8.1',
  title: 'Azure CIS 8.1 Ensure that the expiration date is set on all keys',

  description:
    'Ensure that all keys in Azure Key Vault have an expiration time set.',

  audit: `**From Azure Console**
  
  1. Go to Key vaults
  2. For each Key vault, click on Keys.
  3. Under the Settings section, Make sure Enabled? is set to Yes
  4. Then ensure that each key in the vault has EXPIRATION DATE set as appropriate
  
  **Using Azure Command Line Interface 2.0**  
  Ensure that the output of the below command contains Key ID (kid), enabled status as true and Expiration date (expires) is not empty or null:
  
      az keyvault key list --vault-name <KEYVALUTNAME> --query [*].[{"kid":kid},{"enabled":attributes.enabled},{"expires":attributes.expires}]`,

  rationale:
    'Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration time) attribute identifies the expiration time on or after which the key MUST NOT be used for a cryptographic operation. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration time for all keys. This ensures that the keys cannot be used beyond their assigned lifetimes.',

  remediation: `**From Azure Console**
  
  1. Go to Key vaults
  2. For each Key vault, click on Keys.
  3. Under the Settings section, Make sure Enabled? is set to Yes
  4. Set an appropriate EXPIRATION DATE on all keys.
  
  **Using Azure Command Line Interface 2.0**  
  Update the EXPIRATION DATE for the key using below command.
  
      az keyvault key set-attributes --name <keyName> --vault-name <vaultName> --expires Y-m-d'T'H:M:S'Z'
  
  **Note**:  
  In order to access expiration time on all keys in Azure Key Vault using Microsoft API requires "List" Key permission.  
  To provide required access follow below steps,
  
  1. Go to Key vaults
  2. For each Key vault, click on Access Policy.
  3. Add access policy with Key permission as List`,

  references: [
    'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis',
    'https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-keys',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy',
  ],
  gql: `{
    queryazureKeyVault {
      id
      __typename
      keys {
        attributes {
          enabled
          expires
        }
      }
    }
  }`,
  resource: 'queryazureKeyVault[*]',
  severity: 'high',
  conditions: {
    path: '@keys',
    array_all: {
      and: [
        {
          path: '[*].attributes.enabled',
          equal: true,
        },
        {
          path: '[*].attributes.expires',
          notIn: [null, ''],
        },
      ],
    },
  },
}
