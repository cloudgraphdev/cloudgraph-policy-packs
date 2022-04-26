export default {
  id: 'aws-nist-800-53-rev4-8.5',
  title: 'AWS NIST 8.5 VPC security group inbound rules should not permit ingress from ‘0.0.0.0/0’ to all ports and protocols',
  
  description: 'Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. AWS recommends that no security group allow unrestricted ingress access from 0.0.0.0/0 to all ports. Removing unfettered connectivity to remote console services reduces a server’s exposure to risk.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a port range that includes port *0-65535* and has a *Source* of *0.0.0.0/0*`,
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/home).
  - In the left navigation, select Security Groups.
  - For each security group, perform the steps described below.
      - Select the Security Group, click the Inbound Rules tab, and and click Edit rules.
      - Remove any rules that permit ingress from ‘0.0.0.0/0’ to all ports and protocols.
      - Click Save.
  
  **AWS CLI**
  
  Remove ingress rules which allow connectivity from anywhere to all ports and protocols:
  
     aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=0,IpProtocol=tcp,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}],ToPort=65535'
  
      aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=0,IpProtocol=udp,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}],ToPort=65535'
  
      aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=icmp,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}],ToPort=-1'
  
      aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}],ToPort=-1'
  
      aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=icmpv6,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}],ToPort=-1'`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
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
            and: [
              {
                path: '[*].fromPort',
                in: [0, null],
              },
              {
                path: '[*].toPort',
                in: [65535, null],
              },
            ],
          },
        ],
      },
    },
  },
}
