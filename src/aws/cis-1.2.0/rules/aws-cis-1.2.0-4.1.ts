export default {
  id: 'aws-cis-1.2.0-4.1',
  title:
    'AWS CIS 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
  description: `Security groups provide stateful filtering of ingress/egress network traffic to AWS
  resources. It is recommended that no security group allows unrestricted ingress access to
  port 22.`,
  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a port range that includes port *22* and has a *Source* of *0.0.0.0/0*

  Note: A Port value of *ALL* or a port range such as *0 - 1024* are inclusive of port *22*.`,
  rationale: `Removing unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk.`,
  remediation: `Perform the following to implement the prescribed state:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rules* tab
  6. Identify the rules to be removed
  7. Click the *x* in the *Remove* column
  8. Click *Save*`,
  references: [],
  gql: `{
    queryawsSecurityGroup{
      id
      arn
      accountId
       __typename
      inboundRules{
        source
        toPort
        fromPort
      }
    }
  }`,
  resource: 'queryawsSecurityGroup[*]',
  severity: 'high',
  conditions: {
    not: {
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
  },
}
