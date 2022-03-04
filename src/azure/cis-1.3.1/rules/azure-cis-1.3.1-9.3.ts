export default {
  id: 'azure-cis-1.3.1-9.3',  
  title: 'Azure CIS 9.3 Ensure web app is using the latest version of TLS encryption',
  
  description: 'The TLS(Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards, such as PCI DSS.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on SSL settings
  5. Ensure that Minimum TLS Version set to 1.2 under Protocol Settings
  
  **Using Azure Command Line Interface**  
  To check TLS Version for an existing app, run the following command,
  
      az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query minTlsVersion
  
  The output should return 1.2 if TLS Version is set to 1.2 (Which is latest now).`,
  
  rationale: 'App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on SSL settings
  5. Set Minimum TLS Version to 1.2 under Protocol Settings section
  
  **Using Azure Command Line Interface**
  To set TLS Version for an existing app, run the following command:
  
      az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --min-tls-version 1.2`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl#enforce-tls-versions',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      siteConfig {
        minTlsVersion
      }
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'medium',
  conditions: {
    path: '@.siteConfig.minTlsVersion',
    equal: '1.2',
  },
}
