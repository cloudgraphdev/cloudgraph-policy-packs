// AWS CIS 1.2.0 Rule equivalent 4.3
export default {
  id: 'aws-cis-1.3.0-5.3',
  title:
    'AWS CIS 5.3 Ensure the default security group of every VPC restricts all traffic',
  description: `A VPC comes with a default security group whose initial settings deny all inbound traffic,
  allow all outbound traffic, and allow all traffic between instances assigned to the security
  group. If you don't specify a security group when you launch an instance, the instance is
  automatically assigned to this default security group. Security groups provide stateful
  filtering of ingress/egress network traffic to AWS resources. It is recommended that the
  default security group restrict all traffic.

  The default VPC in every region should have its default security group updated to comply.
  Any newly created VPCs will automatically contain a default security group that will need
  remediation to comply with this recommendation.

  **NOTE:** When implementing this recommendation, VPC flow logging is invaluable in
  determining the least privilege port access required by systems to work properly because it
  can log all packet acceptances and rejections occurring under the current security groups.
  This dramatically reduces the primary barrier to least privilege engineering - discovering
  the minimum ports required by systems in the environment. Even if the VPC flow logging
  recommendation in this benchmark is not adopted as a permanent security measure, it
  should be used during any period of discovery and engineering for least privileged security
  groups.`,
  audit: `Perform the following to determine if the account is configured as prescribed:
  Security Group State

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. Repeat the next steps for all VPCs - including the default VPC in each AWS region:
  3. In the left pane, click *Security Groups*
  4. For each default security group, perform the following:
  5. Select the *default* security group
  6. Click the *Inbound Rules* tab
  7. Ensure no rule exist
  8. Click the *Outbound Rules* tab
  9. Ensure no rules exist

  Security Group Members

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. Repeat the next steps for all default groups in all VPCs - including the default VPC in each AWS region:
  3. In the left pane, click *Security Groups*
  4. Copy the id of the default security group.
  5. Change to the EC2 Management Console at https://console.aws.amazon.com/ec2/v2/home
  6. In the filter column type 'Security Group ID : < security group id from #4 >`,
  rationale: 'Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will, in turn, reduce the exposure of those resources.',
  remediation: `Security Group Members
  Perform the following to implement the prescribed state:

  1. Identify AWS resources that exist within the default security group
  2. Create a set of least privilege security groups for those resources
  3. Place the resources in those security groups
  4. Remove the resources noted in #1 from the default security group

  Security Group State

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. Repeat the next steps for all VPCs - including the default VPC in each AWS region:
  3. In the left pane, click *Security Groups*
  4. For each default security group, perform the following:
  5. Select the *default* security group
  6. Click the *Inbound Rules* tab
  7. Remove any inbound rules
  8. Click the *Outbound Rules* tab
  9. Remove any inbound rules

  Recommended:
  IAM groups allow you to edit the "name" field. After remediating default groups rules for all VPCs in all regions, edit this field to add text similar to "DO NOT USE. DO NOT ADD RULES"`,
  references: [
    'CCE-79201-0',
    'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html',
    'CIS CSC v6.0 #9.2',
  ],
  gql: `{
    queryawsSecurityGroup(filter: { name: { eq: "default" } })   {
      id
      name
      arn
      accountId
       __typename
      inboundRules{
        source
      }
      outboundRules{
        destination
      }
    }
  }`,
  resource: 'queryawsSecurityGroup[*]',
  severity: 'high',
  conditions: {
    not: {
      or: [
        {
          path: '@.inboundRules',
          array_any: {
            path: '[*].source',
            in: ['0.0.0.0/0', '::/0'],
          },
        },
        {
          path: '@.outboundRules',
          array_any: {
            path: '[*].destination',
            in: ['0.0.0.0/0', '::/0'],
          },
        },
      ],
    },
  },
}
