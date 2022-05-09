export default {
  id: 'aws-nist-800-53-rev4-16.4',  
  title: 'CloudFront distribution viewer certificate should use secure TLS protocol versions (1.2 and above)',
  
  description: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible. Versions prior to TLS 1.2 are deprecated and usage may pose security risks.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to AWS CloudFront.
  - Select the Distribution.
  - On the General tab, click Edit.
  - In the Security Policy, select TLS protocol version TLSv1.2_2018 or TLSv1.2_2019 (recommended).
  - Click Yes, Edit.

  **AWS CLI**

  To update your CloudFront viewer certificate to use secure TLS protocol versions (1.2 and above):

  > aws cloudfront update-distribution \
  > [--distribution-config <value>] \
  > --id <value> \
  > [--if-match <value>] \
  > [--default-root-object <value>] \
  > [--cli-input-json <value>] \
  > [--generate-cli-skeleton <value>]`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesViewerProtocolPolicy',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html',
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers',
  ],
  gql: `{  
  queryawsCloudfront {
      id
      arn
      accountId
      __typename
      origins {
      customOriginConfig {
        originSslProtocols {
          items
        }
      }
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {
    array_all: {
      path: '[*].origins.customOriginConfig.originSslProtocols.items',
      array_all: {
        path: '[*]',
        in: ["TLSv1.2", "TLSv1.3"]
      }   
    },
  }
}