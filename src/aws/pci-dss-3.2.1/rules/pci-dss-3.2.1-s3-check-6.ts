export default {
  id: 'aws-pci-dss-3.2.1-s3-check-6',
  title: 'S3 Check 6: S3 Block Public Access setting should be enabled',
  description: `This control checks whether the following public access block settings are configured at the account level.

  - ignorePublicAcls: true,
  - blockPublicPolicy: true
  - blockPublicAcls: true
  - restrictPublicBuckets: true

  The control passes if all of the public access block settings are set to true.

  The control fails if any of the settings are set to false, or if any of the settings are not configured.

  As an AWS best practice, S3 buckets should block public access. Unless you explicitly require everyone on the internet to be able to access your S3 bucket, you should ensure that your S3 bucket is not publicly accessible.`,
  rationale: `This control is related to the following PCI DSS requirements.

  **PCI DSS 1.2.1 - Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**

  If you use S3 buckets to store cardholder data, ensure that the bucket does not allow public access. Public access to your S3 bucket might violate the requirement to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.1 - Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**

  If you use S3 buckets to store cardholder data, ensure that the bucket does not allow public access. Allowing public access to your S3 bucket might violate the requirement to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

  **PCI DSS 1.3.2 - Limit inbound internet traffic to IP addresses within the DMZ.**

  If you use S3 buckets to store cardholder data, ensure that the bucket does not allow public access. Allowing public access to your S3 bucket might violate the requirement to limit inbound traffic to IP addresses within the DMZ.

  **PCI DSS 1.3.4 Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.**

  If you use S3 buckets to store cardholder data, ensure that the bucket does not allow public access. Allowing public access to your S3 bucket might violate the requirement to block unauthorized outbound traffic from the cardholder data environment to the internet.

  **PCI DSS 1.3.6 Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the DMZ and other untrusted networks.**

  If you use S3 buckets to store cardholder data, ensure that the bucket does not allow public access. Allowing public access to your S3 bucket might violate the requirement to place system components that store cardholder data in an internal network zone, segregated from the DMZ and other untrusted networks.`,
  remediation: `**To enable Amazon S3 Block Public Access**

  1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.
  2. In the navigation pane, choose **Block public access (account settings)**.
  3. Choose **Edit**. Then select **Block all public access**.
  4. Choose **Save changes**.

  For more information, see [Using Amazon S3 block public access](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html) in the Amazon Simple Storage Service User Guide.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-s3-6',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html',
  ],
  gql: `{
    queryawsS3 {
      id
      accountId
      arn
      __typename
      blockPublicAcls
      blockPublicPolicy
      ignorePublicAcls
      restrictPublicBuckets
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.blockPublicAcls',
        equal: 'Yes',
      },
      {
        path: '@.blockPublicPolicy',
        equal: 'Yes',
      },
      {
        path: '@.ignorePublicAcls',
        equal: 'Yes',
      },
      {
        path: '@.restrictPublicBuckets',
        equal: 'Yes',
      },
    ],
  },
}
