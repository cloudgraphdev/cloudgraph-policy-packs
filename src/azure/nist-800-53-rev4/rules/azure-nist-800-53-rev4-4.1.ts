//similar to azure pci monitoring-check-3
export default {
  id: 'azure-nist-800-53-rev4-4.1',
  title: 'Azure NIST 4.1 Security Center default policy setting ‘Monitor Network Security Groups’ should be enabled',
  
  description: `When this setting is enabled, it recommends that network security groups be configured 
  to control inbound and outbound traffic to VMs that have public endpoints. Network security groups 
  that are configured for a subnet are inherited by all virtual machine network interfaces unless 
  otherwise specified. In addition to checking that a network security group has been configured, 
  this policy assesses inbound security rules to identify rules that allow incoming traffic.`,

  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**

    - Navigate to Azure Policy.

    - Select the subscription and click Edit assignment.

    - Select Parameters.

    - In Network Security Groups on the subnet level should be enabled, select AuditIfNotExists.

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
        notEqual: 'Network Security Groups on the subnet level should be enabled'
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