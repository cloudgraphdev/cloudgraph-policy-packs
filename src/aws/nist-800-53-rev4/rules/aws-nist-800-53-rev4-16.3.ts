export default {
  id: 'aws-nist-800-53-rev4-16.3',  
  title: 'CloudFront distribution custom origins should use secure TLS protocol versions (1.2 and above)',
  
  description: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible. Versions prior to TLS 1.2 are deprecated and usage may pose security risks.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**

  - Navigate to AWS CloudFront.
  - Select the Distribution.
  - Select the Origins and Origin Groups tab.
  - Select the checkbox for the Origin and select Edit.
  - In the Minimum Origin SSL Protocol, select TLS protocol version TLSv1.2.
  - Click Yes, Edit.

  **AWS CLI**

  To update your CloudFront distribution custom origins to use secure TLS protocol versions (1.2 and above):

  > aws cloudfront update-distribution \
  > [--distribution-config <value>] \
  > --id <value> \
  > [--if-match <value>] \
  > [--default-root-object <value>] \
  > [--cli-input-json <value>] \
  > [--generate-cli-skeleton <value>]`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html#using-https-cloudfront-to-origin-certificate',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
  ],
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename   
      viewerCertificate {
        minimumProtocolVersion
      }
    }      
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {
    path: '@.viewerCertificate.minimumProtocolVersion',
    in: ["TLSv1.2", "TLSv1.3"]
  },
}