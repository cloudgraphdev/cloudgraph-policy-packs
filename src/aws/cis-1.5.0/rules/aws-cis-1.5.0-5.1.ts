export default {
  id: 'aws-cis-1.5.0-5.1',  
  title: 'AWS CIS 5.1 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports',
  
  description: 'The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389.',
  
  audit: `**From Console:**  
  Perform the following to determine if the account is configured as prescribed:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Network ACLs*
  3. For each network ACL, perform the following:
      - Select the network ACL
      - Click the *Inbound Rules* tab
      - Ensure no rule exists that has a port range that includes port *22*, *3389*, or other remote server administration ports for your environment and has a *Source* of *0.0.0.0/0* and shows *ALLOW*
  
  **Note:** A Port value of *ALL* or a port range such as *0-1024* are inclusive of port *22*, *3389*, and other remote server administration ports`,
  
  rationale: 'Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.',
  
  remediation: `**From Console:**  
  Perform the following:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Network ACLs*
  3. For each network ACL to remediate, perform the following:
      - Select the network ACL
      - Click the *Inbound Rules* tab
      - Click *Edit inbound rules*
      - Either A) update the Source field to a range other than 0.0.0.0/0, or, B) Click *Delete* to remove the offending inbound rule
      - Click *Save*`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html',
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html#VPC_Security_Comparison',
  ],
  gql: `{
    queryawsNetworkAcl {
      id
      arn
      accountId
      __typename
      inboundRules {
        source
        fromPort
        toPort
        allowOrDeny
      }
    }
  }`,
  resource: 'queryawsNetworkAcl[*]',
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
            path: '[*].allowOrDeny',
            equal: 'allow',
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
