export default {
  id: 'aws-pci-dss-3.2.1-s3-check-4',
  title: 'S3 Check 4: S3 buckets should have server-side encryption enabled',
  description: `This control checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies put-object requests without server-side encryption.

  When you set default encryption on a bucket, all new objects stored in the bucket are encrypted when they are stored, including clear text PAN data.

  Server-side encryption for all of the objects stored in a bucket can also be enforced using a bucket policy. For more information about server-side encryption, see the Amazon Simple Storage Service User Guide.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 3.4: Render Primary Account Numbers (PAN) unreadable anywhere it is stored (including on portable digital media, backup media, and in logs).**

  If you use an S3 bucket to store credit card Primary Account Numbers (PAN), then to render the PAN unreadable, the bucket default encryption should be enabled and/or the S3 bucket policy should explicitly deny put-object requests without server-side encryption.`,
  remediation: `**To enable default encryption on an S3 bucket**

  1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.
  2. Choose the bucket from the list.
  3. Choose **Properties**.
  4. Choose **Default encryption**.
  5. For the encryption, choose either **AES-256** or **AWS-KMS**.

    - To use keys that are managed by Amazon S3 for default encryption, choose **AES-256**. For more information about using Amazon S3 server-side encryption to encrypt your data, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html).
    - To use keys that are managed by AWS KMS for default encryption, choose **AWS-KMS**. Then choose a master key from the list of the AWS KMS master keys that you have created.
    - Type the Amazon Resource Name (ARN) of the **AWS KMS** key to use. You can find the ARN for your AWS KMS key in the IAM console, under **Encryption keys**. Or, you can choose a key name from the drop-down list.
      **Important**
      If you use the AWS KMS option for your default encryption configuration, you are subject to the RPS (requests per second) limits of AWS KMS. For more information about AWS KMS limits and how to request a limit increase, see the [AWS Key Management Service Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/limits.html).
      For more information about creating an AWS KMS key, see the [AWS Key Management Service Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).
      For more information about using AWS KMS with Amazon S3, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html).

      When enabling default encryption, you might need to update your bucket policy. For more information about moving from bucket policies to default encryption, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-update-bucket-policy).

  6. Choose **Save**.

  For more information about default S3 bucket encryption, see the [Amazon Simple Storage Service User Guide](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html).
  `,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-s3-4',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html',
    'https://docs.aws.amazon.com/kms/latest/developerguide/limits.html',
    'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-update-bucket-policy',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html',
  ],
  gql: `{
    queryawsS3 {
      id
      accountId
      arn
      __typename
      encrypted
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: {
    path: '@.encrypted',
    equal: 'Yes',
  },
}
