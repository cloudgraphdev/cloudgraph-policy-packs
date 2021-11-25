export default {
  id: 'aws-cis-1.2.0-2.1',
  description: 'AWS CIS 2.2 Ensure CloudTrail log file validation is enabled',
  gql: `{
    queryawsCloudtrail {
      id
      __typename
      logFileValidationEnabled
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'warning',
  conditions: {
    path: '@.logFileValidationEnabled',
    equal: 'Yes',
  },
}
