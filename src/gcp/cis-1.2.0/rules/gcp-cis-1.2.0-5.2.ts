export default {
  id: 'gcp-cis-1.2.0-5.2',
  description:
    'GCP CIS 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled',
  gql: `{
    querygcpStorageBucket {
      __typename
      id
      iamConfiguration {
        uniformBucketLevelAccess {
          enabled
        }
      }
    }
  }`,
  resource: 'querygcpStorageBucket[*]',
  severity: 'high',
  conditions: {
    path: '@.iamConfiguration.uniformBucketLevelAccess.enabled',
    equal: true,
  },
}
