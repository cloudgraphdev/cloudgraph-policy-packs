//similar to azure pci monitoring-check-3
export default {
  id: 'azure-nist-800-53-rev4-4.2',  
  title: 'Azure NIST 4.2 Security Center default policy setting ‘Monitor OS Vulnerabilities’ should be enabled',
  
  description: 'When this setting is enabled, it analyzes operating system configurations daily to determine issues that could make the virtual machine vulnerable to attack.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**

    - Navigate to Azure Policy.

    - Select the subscription and click Edit assignment.

    - Select Parameters.

    - In Vulnerability assessment should be enabled on virtual machines, select AuditIfNotExists.

    - Click Review + save > save.

  **Azure CLI**

    - Remediation is not possible via the CLI.`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security-center/tutorial-security-policy',
      'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
  ],
  gql: `{
    queryazurePolicyAssignment {
      id
      __typename
      displayName
      parameters {
        key
        value {
          key
          value
        }
      }
    }
  }`,
  resource: 'queryazurePolicyAssignment[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.displayName',
        notEqual: 'Vulnerability assessment should be enabled on virtual machines'
      },
      {
        path: '@.parameters',
        array_any: {
          and: [
            {
              path: '[*].key',
              equal: 'effect',
            },
            {
              and: [
                {
                  path: '[*].value',
                  array_all: {
                    path: '[*].value',
                    in: ['A','u','d','i','t','I','f','N','o','E','x','s'], // AuditIfNotExists
                  },
                },
              ],
            },
          ],
        },
      },
    ],
  },
} 