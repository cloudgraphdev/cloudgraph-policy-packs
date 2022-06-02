export default {
  id: 'azure-cis-1.3.1-9.6',  
  title: 'Azure CIS 9.6 Ensure that \'PHP version\' is the latest, if used to run the web app (Manual)',
  
  description: 'Periodically newer versions are released for PHP software either due to security flaws or to include additional functionality. Using the latest PHP version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Configuration
  5. Ensure that PHP version set to latest version available under General settings
  
  NOTE: No action is required If PHP version is set to Off as PHP is not used by your web app.
  
  **Using Azure Command Line Interface**
  To check PHP version for an existing app, run the following command,
  
      az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query phpVersion
  
  The output should return the latest available version of PHP.  
  NOTE: No action is required, If the output is empty as PHP is not used by your web app.`,
  
  rationale: 'Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Configuration
  5. Set PHP version to latest version available under General settings
  
  NOTE: No action is required If PHP version is set to Off as PHP is not used by your web app.
  
  **Using Azure Command Line Interface**  
  To see the list of supported runtimes:
  
      az webapp list-runtimes | grep php
  
  To set latest PHP version for an existing app, run the following command:
  
      az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --php-version <VERSION>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources',
  ],
  severity: 'high',
}
