export default {
  id: 'aws-nist-800-53-rev4-4.2',  
  title: 'AWS NIST 4.2 CloudFront viewer protocol policy should be set to https-only or redirect-to-https',
  
  description: 'CloudFront connections should be encrypted during transmission over networks that can be accessed by malicious individuals. A CloudFront distribution should only use HTTPS or Redirect HTTP to HTTPS for communication between viewers and CloudFront.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `AWS Console
  
  - Navigate to [CloudFront](https://console.aws.amazon.com/cloudfront/).
  
  - Follow the steps documented here.
  
  **AWS CLI**
  
  Get the ID of the CloudFront CDN distribution you want to remediate, either via the console or CLI:
  
      aws cloudfront list-distributions --output table --query 'DistributionList.Items[*].Id'
  
  Save the distribution configuration to a file:
  
      aws cloudfront get-distribution-config --id <distribution_id> > distribution-config.json
  
  Modify the configuration file so the ViewerProtocolPolicy attribute is changed from “allow-all” to “https-only” or “redirect-to-https”.
  
  Modify the configuration file to remove the following from the beginning of the file. Note the value for the “Etag” attribute before deleting because it is required for the next command.
  
      {
          "ETag": "ETag_Value",
          "DistributionConfig":
  
  Remove the last brace } at the very end of the configuration file.
  
  Update the distribution configuration from the saved configuration file:
  
      aws cloudfront update-distribution --id <distribution_id> --distribution-config file://distribution-config.json --if-match <etag_attribute>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ],
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      defaultCacheBehavior {
        viewerProtocolPolicy
      }
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: { 
    path: '@.defaultCacheBehavior.viewerProtocolPolicy',
    in: ['https-only', 'redirect-to-https']
  },
}
