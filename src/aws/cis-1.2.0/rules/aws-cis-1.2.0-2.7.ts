export default {
  id: 'aws-cis-1.2.0-2.7',
  description:
    'AWS CIS 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
  gql: `{
    queryawsCloudtrail {
      id
      __typename
			kmsKeyId
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'warning',
  conditions: {
    path: '@.kmsKeyId',
    notEqual: null,
  },
}
