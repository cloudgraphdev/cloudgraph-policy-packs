export default {
  id: 'aws-nist-800-53-rev4-6.1',  
  title: 'AWS NIST 6.1 CloudFront access logging should be enabled',
  
  description: 'CloudFront access logs record information about every user request that CloudFront receives. CloudFront distribution access logging should be enabled in order to track viewer requests for content, analyze statistics, and perform security audits.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to CloudFront.
  - Select the CloudFront distribution you want to update.
  - Click the Distribution Settings button.
  - In the General tab, click the Edit button.
  - In the Logging section, select the On radio button.
  - From the Buckets for Logs drop-down, select the AWS S3 bucket.
  - Click Yes, Edit.
  
  **AWS CLI**
  
  Retrieve configuration information for your distribution.
  
      aws cloudfront get-distribution --id <id> --output json > distro.json
  
  Note the ETag, we’ll use this in a later step.
  
      cat distro.json | jq '.ETag' -r
  
  Separate the distribution config from its metadata.
  
      echo $(cat distro.json | jq '.Distribution.DistributionConfig') > config.json
  
  Update the Logging section to enable access logs.
  
      echo $(cat config.json | jq '.Logging.Enabled = true | .Logging.Bucket = "<bucket-dns-name>"') > config.json
  
  Apply the new configuration.
  
      aws cloudfront update-distribution --id <id> --distribution-config file://config.json --if-match <etag>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HowToUpdateDistribution.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ],  
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      logging {
        enabled
      } 
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {  
    path: '@.logging.enabled',
    equal: true,
  },
}
