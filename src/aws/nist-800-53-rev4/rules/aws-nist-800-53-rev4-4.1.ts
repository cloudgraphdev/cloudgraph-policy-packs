export default {
  id: 'aws-nist-800-53-rev4-4.1',  
  title: 'AWS NIST 4.1 CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only',
  
  description: 'CloudFront connections should be encrypted during transmission over networks that can be accessed by malicious individuals. If a CloudFront distribution uses a custom origin, CloudFront should only use HTTPS to communicate with it. This does not apply if the CloudFront distribution is configured to use S3 as origin.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to CloudFront.
  - Select the ID you want to update. Click the Behaviors tab.
  - Select the behavior and click Edit.
  - In Viewer Protocol policy, select HTTPS Only.
  - Click the Yes, Edit button.
  
  **AWS CLI**
  
  Get the ID of the CloudFront CDN distribution you want to remediate, either via the console or CLI:
  
      aws cloudfront list-distributions --output table --query 'DistributionList.Items[*].Id'
  
  Save the distribution configuration to a file:
  
      ws cloudfront get-distribution-config --id <distribution_id> > distribution-config.json
  
  Modify the configuration file so the OriginProtocolPolicy attribute is changed from “http-only” to “https-only”.
  
  Modify the configuration file to remove the following from the beginning of the file. Note the value for the “Etag” attribute before deleting because it is required for the next command.
  
      {
          "ETag": "ETag_Value",
          "DistributionConfig":
  
  Remove the last brace } at the very end of the configuration file.
  
  Update the distribution configuration from the saved configuration file:
  
      aws cloudfront update-distribution --id <distribution_id> --distribution-config file:///tmp/distribution-config.json --if-match <etag_attribute>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOrigin',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginProtocolPolicy',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ], 
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      origins {  
        domainName
        customOriginConfig {
          originProtocolPolicy
        }
      }
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {  
    path: '@.origins',
    array_all: {
      or: [
        {
          path: '[*].domainName',
          match: /.s3.*.amazonaws.com/,
        },
        {
          path: '[*].customOriginConfig.originProtocolPolicy',
          equal: 'https-only',
        },
      ],  
    },
  },
}
