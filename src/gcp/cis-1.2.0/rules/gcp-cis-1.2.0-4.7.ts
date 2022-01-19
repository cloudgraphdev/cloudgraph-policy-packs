export default {
  id: 'gcp-cis-1.2.0-4.7',
  description:
    'GCP CIS 4.7 Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)',
  gql: `{
    querygcpVmInstance{
      __typename
      id
      disks{
        diskEncryptionKey{
          sha256
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.disks',
    array_any: {
      and: [
        {
          path: '[*].diskEncryptionKey',
          notEqual: null,
        },
        {
          path: '[*].diskEncryptionKey.sha256',
          notIn: [null, ''],
        },
      ],
    },
  },
}
