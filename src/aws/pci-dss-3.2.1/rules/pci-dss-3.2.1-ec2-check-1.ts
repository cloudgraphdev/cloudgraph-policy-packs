export default {
  id: 'aws-pci-dss-3.2.1-ec2-check-1',
  title: 'EC2 Check 1: Amazon EBS snapshots should not be publicly restorable',
  description: `This control checks whether Amazon Elastic Block Store snapshots are not publicly restorable by everyone, which makes them public. Amazon EBS snapshots should not be publicly restorable by everyone unless you explicitly allow it, to avoid accidental exposure of your company’s sensitive data.

  You should also ensure that permission to change Amazon EBS configurations are restricted to authorized AWS accounts only. Learn more about managing Amazon EBS snapshot permissions in the [Amazon EC2 User Guide for Linux Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html).`,
  rationale: `**PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**

  Amazon EBS snapshots are used to back up the data on your Amazon EBS volumes to Amazon S3 at a specific point in time. They can be used to restore previous states of EBS volumes.

  If an Amazon EBS snapshot stores cardholder data, it should not be publicly restorable by everyone. This would violate the requirement to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.1: Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**

  Amazon EBS snapshots are used to back up the data on your Amazon EBS volumes to Amazon S3 at a specific point in time. They can be used to restore previous states of Amazon EBS volumes.

  If an Amazon EBS snapshot stores cardholder data, it should not be publicly restorable by everyone. This would violate the requirement to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

  **PCI DSS 1.3.4: Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.**

  Amazon EBS snapshots are used to back up the data on your Amazon EBS volumes to Amazon S3 at a specific point in time, and can be used to restore previous states of EBS volumes.

  If an Amazon EBS snapshot stores cardholder data, it should not be publicly restorable by everyone. This would violate the requirement to block unauthorized outbound traffic from the cardholder data environment to the internet.

  **PCI DSS 7.2.1: Establish an access control system(s) for systems components that restrict access based on a user’s need to know, and is set to "deny all" unless specifically allowed. This access control system(s) must include the following: Coverage of all system components.**

  Amazon EBS snapshots are used to back up the data on your Amazon EBS volumes to Amazon S3 at a specific point in time. They can be used to restore previous states of Amazon EBS volumes.

  If an Amazon EBS snapshot stores cardholder data, it should not be publicly restorable by everyone. This may violate the requirement to ensure access to systems components is restricted to least privilege necessary, or a user’s need to know.`,
  remediation: `**To make a public Amazon EBS snapshot private**

  1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
  2. In the navigation pane, under **Elastic Block Store**, choose **Snapshots** and then select your public snapshot.
  3. Choose **Actions**, then choose **Modify permissions**
  4. Choose **Private**
  5. (Optional) Add AWS account numbers for authorized accounts to share your snapshot with.
  6. Choose **Save**

  For more information about sharing an Amazon EBS snapshot, see the [Amazon EC2 User Guide for Linux Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html',
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html',
  ],
  gql: `{
    queryawsEbs {
      id
      arn
      accountId
      __typename
      permissions {
        group
        userId
      }
    }
  }`,
  resource: 'queryawsEbs[*]',
  severity: 'low',
  conditions: {
    and: [
      {
        path: '@.permissions',
        isEmpty: false,
      },
      {
        path: '@.permissions',
        array_all: {
          and: [
            { path: '[*].group', notEqual: 'all' },
            {
              path: '[*].userId',
              isEmpty: false,
            },
          ],
        },
      },
    ],
  },
}
