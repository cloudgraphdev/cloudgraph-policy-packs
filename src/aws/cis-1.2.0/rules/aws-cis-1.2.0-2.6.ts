export default {
  id: 'aws-cis-1.2.0-2.6',
  description:
    'AWS CIS 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
  gql: `{
    queryawsCloudtrail {
      id
      __typename
			s3 {
        logging
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    path: '@.s3',
    array_any: {
      path: '[*].logging',
      equal: 'Enabled',
    },
  },
}
