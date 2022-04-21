export default {
  id: 'aws-nist-800-53-rev4-8.9',  
  title: 'AWS NIST 8.9 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 3389 (Remote Desktop Protocol)',

  description: 'Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 3389.',

  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rules* tab
  6. Ensure no rule exists that has a port range that includes port *3389* and has a *Source* of *0.0.0.0/0*

  Note: A *Port* value of *ALL* or a port range such as *1024 - 4098* are inclusive of port *3389*.`,

  rationale: 'Removing unfettered connectivity to remote console services, such as RDP, reduces a server\'s exposure to risk.',

  remediation: `Perform the following to implement the prescribed state:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rules* tab
  6. Identify the rules to be removed
  7. Click the *x* in the *Remove* column
  8. Click *Save*`,

  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules',
      'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/using-network-security.html#updating-security-group-rules',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html',
  ],
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
