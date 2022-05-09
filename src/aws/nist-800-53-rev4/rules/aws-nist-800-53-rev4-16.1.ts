export default {
  id: 'aws-nist-800-53-rev4-16.1',  
  title: 'API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above)',
  
  description: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible. Versions prior to TLS 1.2 are deprecated and usage may pose security risks.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to API Gateway.
  - In the left navigation, select Custom Domain Names.
  - Select the domain name to update.
  - In Domain details, select Edit.
  - In Minimum TLS version, select TLS 1.2 (recommended).
  - Select Save.

  **AWS CLI**

  To update the API Gateway classic custom domains to use secure TLS protocol versions (1.2 and above):
  
  > aws apigateway update-domain-name \
  > --domain-name <value> \
  > --patch-operations op='replace',path='/securityPolicy',value='TLS_1_2'`,
  
  references: [
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html#apigateway-custom-domain-tls-version-how-to',
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html',
      'https://docs.aws.amazon.com/cli/latest/reference/apigateway/update-domain-name.html',
      'https://docs.aws.amazon.com/apigateway/api-reference/link-relation/domainname-update/',
  ],
  gql: `{
  }`,
  resource: '[*]',
  severity: 'medium',
  conditions: {
    
  },
}