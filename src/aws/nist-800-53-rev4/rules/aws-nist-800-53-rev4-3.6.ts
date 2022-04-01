export default {
  id: 'aws-nist-800-53-rev4-3.6',
  title: 'AWS NIST 3.6 S3 bucket server-side encryption should be enabled',
  
  description: 'Enabling server-side encryption (SSE) on S3 buckets at the object level protects data at rest and helps prevent the breach of sensitive information assets. Objects can be encrypted with S3 Managed Keys (SSE-S3), KMS Managed Keys (SSE-KMS), or Customer Provided Keys (SSE-C).',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  Repeat these steps for all impacted S3 buckets.
  
  - Navigate to S3.
  - Select the S3 bucket.
  - Select the Properties tab.
  - Select Default Encryption.
  - Select either AES-256 or AWS-KMS encryption and click Save.
  
  AWS CLI
  Enable AES Encryption on an S3 Bucket:
  
      aws s3api put-bucket-encryption --bucket <bucket name> --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
  
  Enable KMS Encryption on an S3 Bucket:
  
      aws s3api put-bucket-encryption --bucket <bucket name> --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<key id>"}}]}'`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html',
  ],  
  gql: `{
   queryawsS3 {
      id
      arn
      accountId
      __typename
      encrypted
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'high',
  conditions: {
    path: '@.encrypted',
    equal: 'Yes',
  },
}
