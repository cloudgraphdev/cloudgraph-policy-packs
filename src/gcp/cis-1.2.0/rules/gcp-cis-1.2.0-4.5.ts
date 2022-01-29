export default {
  id: 'gcp-cis-1.2.0-4.5',
  description:
    'GCP CIS 4.5 Ensure "Enable connecting to serial ports" is not enabled for VM Instance',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpVmInstance{
      __typename
      id
      metadata{
        items{
          key
          value
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.metadata.items',
    array_any: {
      or: [
        {
          and: [
            {
              path: '[*].key',
              equal: 'serial-port-enable',
            },
            {
              path: '[*].value',
              equal: '0',
            },
          ],
        },
        {
          and: [
            {
              path: '[*].key',
              equal: 'serial-port-enable',
            },
            {
              path: '[*].value',
              equal: 'false',
            },
          ],
        },
      ],
    },
  },
}
