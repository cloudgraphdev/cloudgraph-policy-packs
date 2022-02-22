export default {
  id: 'azure-cis-1.3.1-9.9',  
  title:
    "Azure CIS 9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app",

  description:
    'Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.',

  audit: `**From Azure Console**
    
    1. Login to Azure Portal using https://portal.azure.com
    2. Go to App Services
    3. Click on each App
    4. Under Setting section, Click on Configuration
    5. Ensure that HTTP Version set to 2.0 version under General settings
    
    NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.
    
    **Using Azure Command Line Interface**  
    To check HTTP 2.0 version status for an existing app, run the following command,
    
        az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query http20Enabled
    
    The output should return true if HTTPS 2.0 traffic value is set to On.`,

  rationale: `Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.
    
    HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.`,

  remediation: `**From Azure Console**
    
    1. Login to Azure Portal using https://portal.azure.com
    2. Go to App Services
    3. Click on each App
    4. Under Setting section, Click on Configuration
    5. Set HTTP version to 2.0 under General settings
    
    NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.
    
    **Using Azure Command Line Interface**
    To set HTTP 2.0 version for an existing app, run the following command:
    
        az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --http20-enabled true`,

  references: [
    'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources',
  ],  
  gql: `{
    queryazureAppServiceWebApp {
        id
        __typename
        siteConfig {
          http20Enabled
        }
    }
    }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'high',
  conditions: {
    path: '@.siteConfig.http20Enabled',
    equal: true,
  },
}
