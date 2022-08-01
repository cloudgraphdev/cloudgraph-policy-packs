// Azure CIS 1.3.1 Rule equivalent 9.3
export default {
  id: 'azure-nist-800-53-rev4-4.4',  
  title: 'Azure NIST 4.4 App Service web apps should have \'Minimum TLS Version\' set to \'1.2\'',
  
  description: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  - Navigate to [App Services](https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites).
  - In the left navigation, select TLS/SSL settings.
  - In Minimum TLS Version, select 1.2.
  
  **Using Command Line:**
  
  - To enable TLS 1.2:
  
          az webapp config set --resource-group MyResourceGroup \
                              --name MyResourceName \
                              --min-tls-version 1.2`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings',
      'https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions',
      'https://docs.microsoft.com/en-us/cli/azure/webapp/config?view=azure-cli-latest#az-webapp-config-set',
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
