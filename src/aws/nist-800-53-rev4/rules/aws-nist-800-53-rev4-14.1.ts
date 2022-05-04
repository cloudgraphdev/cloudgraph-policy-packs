// PCI DSS 3.2.1 Rule equivalent cloudfront-check-1
export default {
  id: 'aws-nist-800-53-rev4-14.1',
  title: 'AWS NIST 14.1 CloudFront distributions should be protected by WAFs',
  
  description: 'WAF should be deployed on CloudFront distributions to protect web applications from common web exploits that could affect application availability, compromise security, or consume excessive resources.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [WAF](https://console.aws.amazon.com/wafv2).
  - In the navigation pane, choose Web ACLs.
  - Choose the web ACL that you want to associate with a CloudFront distribution.
  - On the Rules tab, under AWS resources using this web ACL, choose Add association.
  - When prompted, use the Resource list to choose the CloudFront distribution that you want to associate this web ACL with.
  - Choose Add.
  - To associate this web ACL with an additional CloudFront distribution, repeat the last three steps.
  
  **AWS CLI**
  
  Get the ID of the web ACL to associate with the CloudFront distribution:
  
      aws waf list-web-acls --output table --query 'WebACLs[*].WebACLId'
  
  Get the ID of the CloudFront CDN distribution you want to remediate:
  
      aws cloudfront list-distributions --output table --query 'DistributionList.Items[*].Id'
  
  Save the distribution configuration to a file:
  
      aws cloudfront get-distribution-config --id <distribution_id> > distribution-config.json
  
  Modify the configuration file so the WebACLId attribute is changed to the web ACL ID from the first step:
  
      "WebACLId": "df6bd310-6012-4870-0000-123456789012"
  
  Modify the configuration file to remove the following from the beginning of the file. Note the value for the “Etag” attribute before deleting because it is required for the next command.
  
      {
          "ETag": "ETag_Value",
          "DistributionConfig":
  
  Remove the last brace } at the very end of the configuration file.
  
  Update the distribution configuration from the saved configuration file:
  
      aws cloudfront update-distribution --id <distribution_id> --distribution-config file://distribution-config.json --if-match <etag_attribute`,
  
  references: [
      'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html',
      'https://docs.aws.amazon.com/cli/latest/reference/waf/list-web-acls.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ],
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      webAclId
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'high',
  conditions: {
    path: '@.webAclId',
    notIn: [null, 'N/A', '']
  },
}
