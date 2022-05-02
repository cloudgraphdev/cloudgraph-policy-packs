export default {
  id: 'aws-nist-800-53-rev4-8.6',
  title: 'AWS NIST 8.6 VPC security group inbound rules should not permit ingress from a public address to all ports and protocols',
  
  description: 'Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. AWS recommends that no security groups explicitly allow inbound ports.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that permit all ports and protocols`,
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/home).
  - In the left navigation, select Security Groups.
  - For each security group, perform the steps described below.
      - Select the Security Group, click the Inbound Rules tab, and and click Edit rules.
      - Remove any rules that permit ingress from any public address to all ports and protocols.
      - Click Save.

  **Note:** A public CIDR block; is when it's set to anything EXCEPT the following valid blocks:

  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

  **AWS CLI**
  
  Remove all ingress rules which allow connectivity from a public CIDR block to all ports and protocols:

    aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=0,IpProtocol=tcp,IpRanges=[{CidrIp=<cidr>}],Ipv6Ranges=[{CidrIpv6=<v6-cidr>}],ToPort=65535'
    
    aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=0,IpProtocol=udp,IpRanges=[{CidrIp=<cidr>}],Ipv6Ranges=[{CidrIpv6=<v6-cidr>}],ToPort=65535'
    
    aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=icmp,IpRanges=[{CidrIp=<cidr>}],Ipv6Ranges=[{CidrIpv6=<v6-cidr>}],ToPort=-1'
    
    aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=icmpv6,IpRanges=[{CidrIp=<cidr>}],Ipv6Ranges=[{CidrIpv6=<v6-cidr>}],ToPort=-1'
    
    aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions 'FromPort=-1,IpProtocol=-1,IpRanges=[{CidrIp=<cidr>}],Ipv6Ranges=[{CidrIpv6=<v6-cidr>}],ToPort=-1'`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html',
  ],
  gql: `{
    queryawsSecurityGroup {
      id
      arn
      accountId
       __typename
      inboundRules {
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
            notIn: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
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
