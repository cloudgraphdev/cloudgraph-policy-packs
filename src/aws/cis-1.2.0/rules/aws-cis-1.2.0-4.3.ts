export default {
  id: 'aws-cis-1.2.0-4.3',
  description:
    'AWS CIS 4.3 Ensure the default security group of every VPC restricts all traffic (Scored)',
  gql: `{
    queryawsSecurityGroup(filter: { name: { eq: "default" } })   {
      id
      name
      __typename
      inboundRules{
        source
      }
      outboundRules{
        destination
      }
    }
  }`,
  resource: 'queryawsSecurityGroup[*]',
  severity: 'high',
  conditions: {
    not: {
      or: [
        {
          path: '@.inboundRules',
          array_any: {
            path: '[*].source',
            in: ['0.0.0.0/0', '::/0'],
          },
        },
        {
          path: '@.outboundRules',
          array_any: {
            path: '[*].destination',
            in: ['0.0.0.0/0', '::/0'],
          },
        },
      ],
    },
  },
}
