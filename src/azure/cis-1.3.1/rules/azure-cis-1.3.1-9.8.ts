export default {
  id: 'azure-cis-1.3.1-9.8',  
  title: 'Azure CIS 9.8 Ensure that \'Java version\' is the latest, if used to run the web app (Manual)',
  
  description: 'Periodically, newer versions are released for Java software either due to security flaws or to include additional functionality. Using the latest Java version for web apps is recommended in order to take advantage of security fixes, if any, and/or new functionalities of the newer version.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Application settings
  5. Ensure that Java version set to the latest version available under General settings
  
  NOTE: No action is required If Java version is set to Off as Java is not used by your web app.
  
  **Using Azure Command Line Interface**  
  To check Java version for an existing app, run the following command,
  
      az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query javaVersion
  
  The output should return the latest available version of Java.  
  NOTE: No action is required If no output for above command as Java is not used by your web app.`,
  
  rationale: 'Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Application settings
  5. Under General settings, Set Java version to latest version available
  6. Set Java minor version to latest version available
  7. Set Java web container to the latest version of web container available
  
  NOTE: No action is required If Java version is set to Off as Java is not used by your web app.
  
  **Using Azure Command Line Interface**  
  To see the list of supported runtimes:
  
      az webapp list-runtimes | grep java
  
  To set latest Java version for an existing app, run the following command:
  
      az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --java-version '1.8' --java-container 'Tomcat' --java-container-version '<VERSION>'`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources',
  ],
  severity: 'high',
}
