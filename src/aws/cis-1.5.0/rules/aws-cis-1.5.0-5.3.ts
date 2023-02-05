export default {
  id: 'aws-cis-1.5.0-5.3',
  title: 'AWS CIS 5.3 Ensure no security groups allow ingress from ::/0 to remote server administration ports',
  
  description: 'Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH to port *22* and RDP to port *3389*.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rules* tab
  6. Ensure no rule exists that has a port range that includes port 22, 3389, or other remote server administration ports for your environment and has a Source of ::/0
  
  **Note:** A Port value of *ALL* or a port range such as *0-1024* are inclusive of port *22*, *3389*,
  and other remote server administration ports.`,
  
  rationale: 'Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.',
  
  remediation: `Perform the following to implement the prescribed state:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  
  Page 215
  
  4. Select the security group
  5. Click the *Inbound Rules* tab
  6. Click the *Edit inbound rules* button
  7. Identify the rules to be edited or removed
  8. Either A) update the Source field to a range other than ::/0, or, B) Click *Delete* to remove the offending inbound rule
  9. Click *Save rules*`,

  references: ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html#deleting-security-group-rule'],
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
            equal: '::/0',
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
                or: [
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
                ]
              },
            ],
          },
        ],
      },
    },
  },
}
