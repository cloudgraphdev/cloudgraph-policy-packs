export default {
  id: 'aws-cis-1.2.0-2.9',
  description:
    'AWS CIS 2.9 Ensure VPC flow logging is enabled in all VPCs (Scored)',
  gql: `{
    queryawsVpc {
      id
      __typename
      flowLogs {
        resourceId
      }
    }
  }`,
  resource: 'queryawsVpc[*]',
  severity: 'medium',
  conditions: {
    path: '@.flowLogs',
    isEmpty: false,
  },
}
