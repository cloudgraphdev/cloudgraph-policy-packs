export default {
  id: 'aws-cis-1.4.0-2.1.1',
  title: 'AWS CIS 2.1.1 Ensure all S3 buckets employ encryption-at-rest (Manual)',

  description: 'Amazon S3 provides a variety of no, or low, cost encryption options to protect data at rest.',

  audit: `**From Console:**
    
    1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
    2. Select the Check box next to the Bucket.
    3. Click on 'Properties'.
    4. Verify that Default Encryption displays either AES-256 or AWS-KMS.
    5. Repeat for all the buckets in your AWS account.
    
    **From Command Line:**
    
    1. Run command to list buckets
    
            aws s3 ls
    
    2. For each bucket, run
    
            aws s3api get-bucket-encryption --bucket <bucket name>
    
    3. Verify that either
    
            "SSEAlgorithm": "AES256"
    
        or
    
            "SSEAlgorithm": "aws:kms" is displayed.`,

  rationale: 'Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.',

  remediation: `**From Console:**
    
    1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
    2. Select the Check box next to the Bucket.
    3. Click on 'Properties'.
    4. Click on Default Encryption.
    5. Select either AES-256 or AWS-KMS
    6. Click Save
    7. Repeat for all the buckets in your AWS account lacking encryption.
    
    **From Command Line:**
    
    Run either
    
        aws s3api put-bucket-encryption --bucket <bucket name> --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
    
    or
    
        aws s3api put-bucket-encryption --bucket <bucket name> --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms","KMSMasterKeyID": "aws/s3"}}]}'
    
    **Note:** the KMSMasterKeyID can be set to the master key of your choosing; aws/s3 is an AWS preconfigured default.`,

  references: [
    'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-related-resources',
  ],

  severity: 'medium',
}
