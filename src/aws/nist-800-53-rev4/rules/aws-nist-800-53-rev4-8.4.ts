export default {
  id: 'aws-nist-800-53-rev4-8.4',
  title: 'AWS NIST 8.4 VPC network ACLs should not allow ingress from 0.0.0.0/0 to TCP/UDP port 3389',
  
  description: 'Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.',
  
  audit: '',
  
  rationale: 'Removing unfettered connectivity to remote console services, such as SSH, reduces a server\'s exposure to risk.',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/).
  - In the left navigation, select Network ACLs.
  - For each Network ACL, perform the steps described below.
  - Select the Network ACL, click the Inbound Rules tab, and and click Edit Inbound rules.
  - Remove any rule that permits unrestricted ingress from 0.0.0.0/0 to TCP/UDP port 3389.
  - Click Save.
  
  **AWS CLI**
  
  Remove the inbound rule(s) that permits unrestricted ingress from 0.0.0.0/0 to TCP/UDP port 3389 from the selected Network ACLs:
  
      aws ec2 delete-network-acl-entry --network-acl-id <network-acl-id> --ingress --rule-number <rule_number>`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html',
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html#VPC_Security_Comparison',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-network-acl-entry.html',
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
