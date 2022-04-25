export default {
  id: 'aws-nist-800-53-rev4-8.38',
  title: 'AWS NIST 8.38 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5900 (Virtual Network Computing)',
  
  description: 'Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. AWS recommends that no security group allow unrestricted ingress access to port 5900. Removing unfettered connectivity to remote console services reduces a server’s exposure to risk.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a port range that includes port *5900* and has a *Source* of *0.0.0.0/0*`,
  
  rationale: 'Removing unfettered connectivity to remote console services, such as Virtual Network Computing, reduces a server\'s exposure to risk.',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/).
  - In the left navigation pane, click Security Groups.
  - Remove any rules that include port 5900 and have a source of 0.0.0.0/0.
  - Click Save.
  
  **AWS CLI**
  
  List all security groups with an ingress rule of 0.0.0.0/0:
  
      aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0' --query "SecurityGroups[*].{Name:GroupName,ID:GroupId}"
  
  Remove the inbound rule(s) that permits unrestricted ingress to port 5900:
  
      ws ec2 revoke-security-group-ingress --region <region> --group-name <group_name> --protocol <protocol> --port 5900 --cidr 0.0.0.0/0
  
  Optionally add a more restrictive ingress rule to the selected Security Group:
  
      aws ec2 authorize-security-group-ingress --region <region> --group-name <group_name> --protocol <protocol> --port 5900 --cidr <cidr_block>`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules',
      'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/working-with-security-groups.html#updating-security-group-rules',
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
                    lessThanInclusive: 5900,
                  },
                  {
                    path: '[*].toPort',
                    greaterThanInclusive: 5900,
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
