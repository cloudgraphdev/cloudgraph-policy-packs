export default {
  id: 'aws-pci-dss-3.2.1-s3-check-3',
  title: 'S3 Check 3: S3 buckets should have cross-region replication enabled',
  description: `This control checks whether S3 buckets have cross-region replication enabled.

  PCI DSS does not require data replication or highly available configurations. However, this check aligns with AWS best practices for this control.

  In addition to availability, you should consider other systems hardening settings.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 2.2: Develop configuration standards for all system components. Assure that these standards address all known security vulnerabilities and are consistent with industry-accepted system hardening standards.**

  Enabling cross-Region replication on S3 buckets ensures that multiple versions of the data are available in different distinct Regions. This allows you to store data at even greater distances, minimize latency, increase operational efficiency, and protect against DDoS and data corruption events.

  This is one method used to implement system hardening configuration.`,
  remediation: `**To enable S3 bucket replication**

  1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.
  2. Choose the S3 bucket that does not have cross-region replication enabled.
  3. Choose **Management**, then choose **Replication**.
  4. Choose **Add rule**. If versioning is not already enabled, you are prompted to enable it.
  5. Choose your source bucket - **Entire bucket**.
  6. Choose your destination bucket. If versioning is not already enabled on the destination bucket for your account, you are prompted to enable it.
  7. Choose an IAM role. For more information on setting up permissions for replication, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/setting-repl-config-perm-overview.html).
  8. Enter a rule name, choose **Enabled** for the status, then choose **Next**.
  9. Choose **Save**.

  For more information about replication, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-s3-3',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/setting-repl-config-perm-overview.html',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html',
  ],
  gql: `{
    queryawsS3 {
      id
      accountId
      arn
      __typename
      crossRegionReplication
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'low',
  conditions: {
    path: '@.crossRegionReplication',
    equal: 'Enabled',
  },
}
