export default {
  id: 'gcp-cis-1.2.0-4.9',
  description:
    'GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpVmInstance {
      id
      __typename
      name
      networkInterfaces {
        accessConfigs {
          name
          natIP
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    not: {
      and: [
        {
          path: '@.name',
          mismatch: /^gke-.*$/,
        },
        {
          path: '@.networkInterfaces',
          array_any: {
            path: '[*].accessConfigs',
            array_any: {
              and: [
                {
                  path: '[*].natIP',
                  notEqual: null,
                },
                {
                  path: '[*].natIP',
                  notEqual: '',
                },
              ],
            },
          },
        },
      ],
    },
  },
}
