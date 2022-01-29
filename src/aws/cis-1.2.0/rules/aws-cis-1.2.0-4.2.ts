export default {
  id: 'aws-cis-1.2.0-4.2',
  description:
    'AWS CIS 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)',
  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at
      https://console.aws.amazon.com/vpc/home
  2. In the left pane, click Security Groups
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the Inbound Rules tab
  6. Ensure no rule exists that has a port range that includes port 3389 and has a Source of 0.0.0.0/0
  
  Note: A Port value of ALL or a port range such as 1024 - 4098 are inclusive of port 3389.`,
  rationale: `Removing unfettered connectivity to remote console services, such as RDP, reduces a server's exposure to risk.`,
  remediation: `Perform the following to implement the prescribed state:

  1. Login to the AWS Management Console at
      https://console.aws.amazon.com/vpc/home
  2. In the left pane, click Security Groups
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the Inbound Rules tab
  6. Identify the rules to be removed
  7. Click the x in the Remove column
  8. Click Save`,
  references: [],
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
                    lessThanInclusive: 3389,
                  },
                  {
                    path: '[*].toPort',
                    greaterThanInclusive: 3389,
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
