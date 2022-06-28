export default {
  id: 'azure-pci-dss-3.2.1-monitoring-check-3',  
  title: 'Monitoring Check 3: Security Center default policy setting ‘Monitor Endpoint Protection’ should be enabled',
  
  description: 'When this setting is enabled, it recommends endpoint protection be provisioned for all Windows virtual machines to help identify and remove viruses, spyware, and other malicious software.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  - Navigate to Azure Policy.
  - Select the subscription and click Edit assignment.
  - Select Parameters.
  - In Monitor missing Endpoint Protection in Azure Security Center, select AuditIfNotExists.
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
        notEqual: 'Monitor missing Endpoint Protection in Azure Security Center'
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