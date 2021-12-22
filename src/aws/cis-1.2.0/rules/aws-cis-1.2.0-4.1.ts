export default {
  id: 'aws-cis-1.2.0-4.1',
  description:
    'AWS CIS 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)',
  gql: `{
    queryawsSecurityGroup{    
      id
      __typename
      inboundRules{      
        source
        toPort
        fromPort
      }
    }
  }`,
  resource: 'queryawsSecurityGroup[*]',
  severity: 'danger',
  conditions: {
    path: '@.inboundRules',
    array_any: {
      and: [
        {
          path: '[*].source',
          in: ['0.0.0.0/0', '::/0'],
        },
        {
          or: [
            {
              and: [
                {
                  path: '[*].fromPort',
                  equal: null,
                },
                {
                  path: '[*].toPort',
                  equal: null,
                },
              ],
            },
            {
              and: [
                {
                  path: '[*].fromPort',
                  lessThanInclusive: 22,
                },
                {
                  path: '[*].toPort',
                  greaterThanInclusive: 22,
                },
              ],
            },
          ],
        },
      ],
    },
  },
}
