export default {
  id: 'aws-pci-dss-3.2.1-ec2-check-4',
  title: 'EC2 Check 4: Unused EC2 EIPs should be removed',
  description: `This control checks whether Elastic IP addresses that are allocated to a VPC are attached to Amazon EC2 instances or in-use elastic network interfaces (ENIs).

  A failed finding indicates you may have unused Amazon EC2 EIPs.

  This will help you maintain an accurate asset inventory of EIPs in your cardholder data environment (CDE).`,
  rationale: `**PCI DSS 2.4: Maintain an inventory of system components that are in scope for PCI DSS.**
  If an EIP is not attached to an Amazon EC2 instance, this is an indication that it is no longer in use.

  Unless there is a business need to retain them, you should remove unused resources to maintain an accurate inventory of system components.`,
  remediaton: `If you no longer need an Elastic IP address, Security Hub recommends that you release it (the address must not be associated with an instance).

  **To release an Elastic IP address using the console**

  1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.

  2. In the navigation pane, under **Network & Security**, choose **Elastic IPs**.

  3. Choose the **Elastic IP address**, choose **Actions**, and then choose **Release Elastic IP address**.

  4. When prompted, choose **Release**.

  For more information, see the information on releasing Elastic IP addresses in the [Amazon EC2 User Guide for Linux Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-releasing).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-releasing',
  ],
  gql: `{
    queryawsEip {
      id
      arn
      accountId
      __typename
      instanceId
      ec2Instance {
        arn
      }
    }
  }`,
  resource: 'queryawsEip[*]',
  severity: 'low',
  conditions: {
    and: [
      {
        path: '@.instanceId',
        notEqual: null,
      },
      {
        path: '@.ec2Instance',
        isEmpty: false,
      },
    ],
  },
}
