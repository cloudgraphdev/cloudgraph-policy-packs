export default {
  id: 'azure-cis-1.3.1-9.4',  
  title: 'Azure CIS 9.4 Ensure the web app has \'Client Certificates (Incoming client certificates)\' set to \'On\'',
  
  description: 'Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Configuration
  5. Ensure that the option Client certificate mode located under Incoming client certificates is set to Require
  
  **Using Azure Command Line Interface**  
  To check Incoming client certificates value for an existing app, run the following command,
  
      az webapp show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query clientCertEnabled
  
  The output should return true if Incoming client certificates value is set to On.`,
  
  rationale: 'The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled, then only an authenticated client who has valid certificates can access the app.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Configuration
  5. Set the option Client certificate mode located under Incoming client certificates is set to Require
  
  **Using Azure Command Line Interface**  
  To set Incoming client certificates value for an existing app, run the following command:
  
      az webapp update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --set clientCertEnabled=true`,
  
  references: ['https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit'],
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      clientCertEnabled
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'high',
  conditions: {
    path: '@.clientCertEnabled',
    equal: true,
  },
}
