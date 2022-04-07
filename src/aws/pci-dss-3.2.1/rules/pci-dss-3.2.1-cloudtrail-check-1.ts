export default {
  id: 'aws-pci-dss-3.2.1-cloudtrail-check-1',
  title:
    'CloudTrail Check 1: CloudTrail logs should be encrypted at rest using AWS KMS keys',
  description: `This control checks whether AWS CloudTrail is configured to use the server-side encryption (SSE) AWS KMS key encryption.

  If you are only using the default encryption option, you can choose to disable this check.`,
  rationale: `PCI DSS 3.4: Render Primary Account Numbers (PAN) unreadable anywhere it is stored (including on portable digital media, backup media, and in logs).
  If you are using AWS services to process and store PAN, your CloudTrail logs should be encrypted at rest. Encrypting logs ensures that if logs capture PAN(s), the PAN(s) are protected.

  By default, the log files delivered by CloudTrail to your S3 bucket are encrypted using Amazon server-side encryption with Amazon S3-managed encryption keys (SSE-S3). See the Amazon Simple Storage Service User Guide.

  You can configure CloudTrail logs to leverage customer managed keys to further protect CloudTrail logs.

  These are methods used to render PAN unreadable.`,
  remediation: `To remediate this issue, you enable encryption for your CloudTrail log files.

  For details on how to encrypt CloudTrail log files with AWS KMS managed keys (SSE-KMS), see [Encrypting CloudTrail log files with AWS KMS–managed keys (SSE-KMS)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
  in the AWS CloudTrail User Guide.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
      __typename
      kmsKeyId
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    path: '@.kmsKeyId',
    notIn: [null, ''],
  },
}
