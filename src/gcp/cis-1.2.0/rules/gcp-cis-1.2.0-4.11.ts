export default {
  id: 'gcp-cis-1.2.0-4.11',
  description:
    'GCP CIS 4.11 Ensure that Compute instances have Confidential Computing enabled',
  gql: `{
    querygcpVmInstance {
      id
      __typename
      confidentialInstanceConfig {
        enableConfidentialCompute
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.confidentialInstanceConfig.enableConfidentialCompute',
    equal: true,
  },
}