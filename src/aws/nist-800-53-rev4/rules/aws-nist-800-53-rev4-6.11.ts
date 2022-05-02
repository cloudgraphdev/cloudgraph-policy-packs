export default {
  id: 'aws-nist-800-53-rev4-6.11',  
  title: 'AWS NIST 6.11 S3 bucket access logging should be enabled on S3 buckets that store CloudTrail log files',
  
  description: 'It is recommended that users enable bucket access logging on the S3 bucket storing CloudTrail log data. Such logging tracks access requests to this S3 bucket and can be useful in security and incident response workflows.',
  
  audit: `Perform the following ensure the CloudTrail S3 bucket has access logging is enabled:
  Via the management Console
  
  1. Go to the Amazon CloudTrail console at https://console.aws.amazon.com/cloudtrail/home
  2. In the API activity history pane on the left, click Trails
  3. In the Trails pane, note the bucket names in the S3 bucket column
  4. Sign in to the AWS Management Console and open the S3 console at https://console.aws.amazon.com/s3.
  5. Under *All Buckets* click on a target S3 bucket
  6. Click on *Properties* in the top right of the console
  7. Under *Bucket: <bucket_name>* click on *Logging*
  8. Ensure *Enabled* is checked.
  
  Via CLI
  
  1. Get the name of the S3 bucket that CloudTrail is logging to:
  
  aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'
  
  2. Ensure Bucket Logging is enabled:
  
  aws s3api get-bucket-logging --bucket <s3_bucket_for_cloudtrail>
  
  Ensure command does not return empty output.
  Sample Output for a bucket with logging enabled:
  
  {
      "LoggingEnabled": {
      "TargetPrefix": "<Prefix_Test>",
      "TargetBucket": "<Bucket_name_for_Storing_Logs>"
      }
  }`,
  
  rationale: 'By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.',
  
  remediation: `**AWS Console**
  
  - Navigate to CloudTrail.
  - Create a CloudTrail trail as specified here.
  - In storage location, note the name of the S3 bucket.
  - Navigate to S3.
  - Select the S3 bucket that you attached to your CloudTrail trail from the previous step.
  - Click Properties.
  - Edit your S3 bucket to have Server access logging enabled as described here.*
  
  **AWS CLI**
  
  Get the name of the S3 bucket that CloudTrail is logging to:
  
      aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'
  
  Ensure Bucket Logging is enabled:
  
      aws s3api get-bucket-logging --bucket <s3_bucket_for_cloudtrail>
  
  Ensure command does not return empty output. Sample output for a bucket with logging enabled:
  
      { "LoggingEnabled": { "TargetPrefix": "<Prefix_Test>", "TargetBucket": "<Bucket_name_for_Storing_Logs>" } }
  
  If the command returns an empty output, run the following command to enable logging:
  
      aws s3api put-bucket-logging --bucket <s3_bucket_for_cloudtrail> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket": <Bucket_name_for_Storing_Logs>,"TargetPrefix":"/"}}'`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/server-access-logging.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/index.html#cli-aws-cloudtrail',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-acl.html#description',
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
       __typename
			s3 {
        logging
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    path: '@.s3',
    array_all: {
      path: '[*].logging',
      equal: 'Enabled',
    },
  },
}
