export default {
  id: 'aws-nist-800-53-rev4-12.1',  
  title: 'CloudFront distributions should have geo-restrictions specified',
  
  description: `CloudFront distributions should enable geo-restriction when an organization needs to 
  prevent users in specific geographic locations from accessing content. For example, 
  if an organization has rights to distribute content in only one country, geo restriction should be 
  enabled to allow access only from users in the whitelisted country. Or if the organization cannot 
  distribute content in a particular country, geo restriction should deny access from users in the 
  blacklisted country.`,

  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**  

  - Navigate to CloudFront.
  - Select the distribution that you want to update.
  - In the Distribution Settings pane, select the Restrictions tab > Edit.
  - Enter the applicable values. For more information, refer to Restrictions.
  - Choose Yes, Edit.
  
  **AWS CLI**
  - Submit a GetDistributionConfig request to get the current configuration and an Etag header for the distribution.
    - > get-distribution-config --id <value> 
  - Update the returned XML to include the CloudFront should have geo-restrictions specified.
  - Submit an UpdateDistribution request to update the configuration for your distribution. Refer to here for more information.`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesRestrictions',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ],
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      geoRestriction {
        restrictionType        
      }
    }    
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {
    path: '@.geoRestriction',
      array_all: {
        path: '[*].restrictionType',
        notIn: 'none'
      },
  },
}