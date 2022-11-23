// AWS CIS 1.4.0 Rule equivalent 3.6
export default {
  id: 'aws-cis-1.5.0-3.6',
  title:
    'AWS CIS 3.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
  description: `S3 Bucket Access Logging generates a log that contains access records for each request
  made to your S3 bucket. An access log record contains details about the request, such as the
  request type, the resources specified in the request worked, and the time and date the
  request was processed. It is recommended that bucket access logging be enabled on the
  CloudTrail S3 bucket.`,
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
  remediation: `Perform the following to enable S3 bucket logging:
  Via the Management Console

  1. Sign in to the AWS Management Console and open the S3 console at https://console.aws.amazon.com/s3
  2. Under *All Buckets* click on the target S3 bucket
  3. Click on *Properties* in the top right of the console
  4. Under *Bucket: <s3_bucket_for_cloudtrail>* click on *Logging*
  5. Configure bucket logging
      1. Click on *Enabled* checkbox
      2. Select Target Bucket from list
      3. Enter a Target Prefix
  6. Click *Save*`,
  references: ['CCE- 78918 - 0', 'https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html'],
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
  severity: 'high',
  conditions: {
    path: '@.s3',
    array_any: {
      path: '[*].logging',
      equal: 'Enabled',
    },
  },
}
