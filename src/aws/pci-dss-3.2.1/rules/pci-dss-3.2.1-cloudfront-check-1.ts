export default {
  id: 'aws-pci-dss-3.2.1-cloudfront-check-1',
  title:
    'Cloudfront Check 1: Cloudfront distributions should be protected by WAFs',
  description: `WAF should be deployed on Cloudfront distributions to protect web applications from common web exploits that could affect application availability, compromise security, or consume excessive resources.`,
  remediation: `
  1. Navigate to WAF.

  2. In the navigation pane, choose Web ACLs.
  
  3. Choose the web ACL that you want to associate with a CloudFront distribution.
  
  4. On the Rules tab, under AWS resources using this web ACL, choose Add association.
  
  5. When prompted, use the Resource list to choose the CloudFront distribution that you want to associate this web ACL with.
  
  6. Choose Add.
  
  To associate this web ACL with an additional CloudFront distribution, repeat the last three steps.`,
  references: ['https://d1.awsstatic.com/whitepapers/compliance/pci-dss-compliance-on-aws.pdf'],
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
