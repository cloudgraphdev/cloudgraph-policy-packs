export default {
  id: 'azure-cis-1.3.1-9.2',  
  title: 'Azure CIS 9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service',
  
  description: 'Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on SSL settings
  5. Ensure that HTTPS Only set to On under Protocol Settings
  
  **Using Azure Command Line Interface**  
  To check HTTPS-only traffic value for an existing app, run the following command,
  
      az webapp show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query httpsOnly
  
  The output should return true if HTTPS-only traffic value is set to On.`,
  
  rationale: 'Enabling HTTPS-only traffic will redirect all non-secure HTTP request to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated. So it is important to support HTTPS for the security benefits.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on SSL settings
  5. Set HTTPS Only to On under Protocol Settings section
  
  Using Azure Command Line Interface To set HTTPS-only traffic value for an existing app, run the following command:
  
      az webapp update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --set httpsOnly=true`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl#enforce-https',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      httpsOnly
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'medium',
  conditions: {
    path: '@.httpsOnly',
    equal: true,
  },
}
