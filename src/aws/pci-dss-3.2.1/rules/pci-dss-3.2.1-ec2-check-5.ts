export default {
  id: 'aws-pci-dss-3.2.1-ec2-check-5',
  title:
    'EC2 Check 5: Security groups should not allow ingress from 0.0.0.0/0 to port 22',
  description: `This control checks whether security groups in use disallow unrestricted incoming SSH traffic.

  It does not evaluate outbound traffic.

  Note that security groups are stateful. If you send a request from your instance, the response traffic for that request is allowed to flow in regardless of inbound security group rules. Responses to allowed inbound traffic are allowed to flow out regardless of outbound rules. To learn more about security groups, see [Security groups for your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) in the Amazon VPC User Guide.`,
  rationale: `**PCI DSS 1.2.1 - Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**
  You might allow SSH traffic to your instances that are in your defined CDE. If so, restrict the inbound SSH source from 0.0.0.0/0 (anywhere) to a specific IP address or range. Leaving unrestricted access to SSH might violate the requirement to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.1 - Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**
  You might allow SSH traffic to your instances that are in your defined CDE. If so, restrict the inbound SSH source from 0.0.0.0/0 (anywhere) to a specific IP address or range. Leaving unrestricted access to SSH might violate the requirement to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

  **PCI DSS 2.2.2 Enable only necessary services, protocols, daemons, etc., as required for the function of the system.**
  You might allow SSH traffic to your instances that are in your defined CDE. If so, restrict the inbound SSH source from 0.0.0.0/0 (anywhere) to a specific IP address or range as required for the function of the security group. Within a CDE, a security group could be considered a system component, which should be hardened appropriately. Leaving unrestricted access to SSH might violate the requirement to enable only the necessary services, protocols, daemons, etc., that are required for the function of the system.`,
  remediaton: `**To remove access to port 22 from a security group**

  1. Open the Amazon VPC console at https://console.aws.amazon.com/vpc/.

  1. In the navigation pane, under **Security**, choose **Security groups**.

  1. Select a security group.

  1. In the bottom section of the page, choose **Inbound rules**.

  1. Choose **Edit inbound rules**.

  1. Identify the rule that allows access through port 22 and then choose the X to remove it.

  1. Choose **Save rules**.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
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
                    lessThanInclusive: 22,
                  },
                  {
                    path: '[*].toPort',
                    greaterThanInclusive: 22,
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
