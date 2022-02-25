export default {
  id: 'aws-pci-dss-3.2.1-ec2-check-2',
  title:
    'EC2 Check 2: VPC default security group should prohibit inbound and outbound traffic',
  description: `This control checks that the default security group of a VPC does not allow inbound or outbound traffic.

  It does not check for access restrictions for other security groups that are not default, and other VPC configurations.`,
  rationale: `**PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**

  If a service that is in scope for PCI DSS is associated with the default security group, the default rules for the security group will allow all outbound traffic. The rules also allow all inbound traffic from network interfaces (and their associated instances) that are assigned to the same security group.

  You should change the default security group rules setting to restrict inbound and outbound traffic. Using the default might violate the requirement to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.4: Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.**

  If a service that is in scope for PCI DSS is associated with the default security group, the default rules for the security group will allow all outbound traffic. The rules also allow all inbound traffic from network interfaces (and their associated instances) that are assigned to the same security group.

  You should change the default security group rules setting to restrict unauthorized inbound and outbound traffic. Using the default may violate the requirement to block unauthorized outbound traffic from the cardholder data environment to the internet.

  **PCI DSS 2.1: Always change vendor-supplied defaults and remove or disable unnecessary default accounts before installing a system on the network.**

  If a service that is in scope for PCI DSS is associated with the default security group, the default rules for the security group will allow all outbound traffic. The rules also allow all inbound traffic from network interfaces (and their associated instances) that are assigned to the same security group.

  You should change the default security group rules setting to restrict inbound and outbound traffic. Using the default may violate the requirement to remove or disable unnecessary default accounts.`,
  remediation: `
  To remediate this issue, create new security groups and assign those security groups to your resources. To prevent the default security groups from being used, remove their inbound and outbound rules.

  **To create new security groups and assign them to your resources**

  1. Open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
  2. In the navigation pane, choose **Security groups**. View the default security groups details to see the resources that are assigned to them.
  3. Create a set of least-privilege security groups for the resources. For details on how to create security groups, see [Creating a security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#CreatingSecurityGroups) in the Amazon VPC User Guide.
  4. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
  5. On the Amazon EC2 console, change the security group for the resources that use the default security groups to the least-privilege security group you created. See [Changing an instance's security groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#SG_Changing_Group_Membership) in the Amazon VPC User Guide.

  After you assign the new security groups to the resources, remove the inbound and outbound rules from the default security groups. This ensures that the default security groups are not used.

  **To remove the rules from the default security group**

  1. Open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
  2. In the navigation pane, choose Security groups.
  3. Select a default security group, and choose the Inbound rules tab. Choose Edit inbound rules. Then delete all of the inbound rules. Choose Save rules.
  4. Repeat the previous step for each default security group.
  5. Select a default security group and choose the Outbound rules tab. Choose Edit outbound rules. Then delete all of the outbound rules. Choose Save rules.
  6. Repeat the previous step for each default security group.

  For more information about working with security groups in Amazon VPC, see the [Amazon VPC User Guide](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#WorkingWithSecurityGroups).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#CreatingSecurityGroups',
    'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#SG_Changing_Group_Membership',
    'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#WorkingWithSecurityGroups',
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
  severity: 'medium',
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
