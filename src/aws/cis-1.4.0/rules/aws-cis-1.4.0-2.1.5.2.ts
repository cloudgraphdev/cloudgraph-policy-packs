export default {
  id: 'aws-cis-1.4.0-2.1.5.2',  
  title: 'AWS CIS 2.1.5.2 Ensure that S3 Buckets are configured with \'Block public access (bucket settings)\' (bucket settings)',
  
  description: 'Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account.',
  
  audit: `**From Console:**
  
  1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
  2. Select the Check box next to the Bucket.
  3. Click on 'Edit public access settings'.
  4. Ensure that block public access settings are set appropriately for this bucket
  5. Repeat for all the buckets in your AWS account.
  
  **From Command Line:**
  
  1. List all of the S3 Buckets
  
          aws s3 ls
  
  2. Find the public access setting on that bucket
  
          aws s3api get-public-access-block --bucket <name-of-the-bucket>
  
  Output if Block Public access is enabled:
  
          { 
              "PublicAccessBlockConfiguration": { 
                  "BlockPublicAcls": true,
                  "IgnorePublicAcls": true,
                  "BlockPublicPolicy": true,
                  "RestrictPublicBuckets": true 
              } 
          }
  
  If the output reads false for the separate configuration settings then proceed to the remediation.`,
  
  rationale: `Amazon S3 'Block public access (bucket settings)' prevents the accidental or malicious public exposure of data contained within the respective bucket(s).

  Whether blocking public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.`,
  
  remediation: `**From Console:**
  
  1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
  2. Select the Check box next to the Bucket.
  3. Click on 'Edit public access settings'.
  4. Click 'Block all public access'
  5. Repeat for all the buckets in your AWS account that contain sensitive data.
  
  **From Command Line:**
  
  1. List all of the S3 Buckets
  
          aws s3 ls
  
  2. Set the Block Public Access to true on that bucket
  
          aws s3api put-public-access-block --bucket <name-of-bucket> --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
  
  references: ['https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access-account.html'],
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
      __typename
      blockPublicAcls
      ignorePublicAcls
      blockPublicPolicy
      restrictPublicBuckets
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.blockPublicAcls',
        equal: 'Yes',
      },
      {
        path: '@.ignorePublicAcls',
        equal: 'Yes',
      },
      {
        path: '@.blockPublicPolicy',
        equal: 'Yes',
      },
      {
        path: '@.restrictPublicBuckets',
        equal: 'Yes',
      },
    ],
  },
}