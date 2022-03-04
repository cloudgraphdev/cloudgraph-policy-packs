export default {
  id: 'azure-cis-1.3.1-9.7',  
  title: "Azure CIS 9.7 Ensure that 'Python version' is the latest, if used to run the web app (Manual)",

  description: 'Periodically, newer versions are released for Python software either due to security flaws or to include additional functionality. Using the latest Python version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.',

  audit: `Using Console:
    
    1. Login to Azure Portal using https://portal.azure.com
    2. Go to App Services
    3. Click on each App
    4. Under Setting section, Click on Application settings
    5. Ensure that Python version set to the latest version available under General settings
    
    NOTE: No action is required, If Python version is set to Off as Python is not used by your web app.
    
    Using Command line:  
    To check Python version for an existing app, run the following command,
    
        az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query pythonVersion
    
    The output should return the latest available version of Python.  
    NOTE: No action is required, If the output is empty as Python is not used by your web app.`,

  rationale: 'Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.',

  remediation: `Using Console:
    
    1. Login to Azure Portal using https://portal.azure.com
    2. Go to App Services
    3. Click on each App
    4. Under Setting section, Click on Application settings
    5. Set Python version to latest version available under General settings
    
    NOTE: No action is required, If Python version is set to Off as Python is not used by your web app.  
    Using Command Line:  
    To see the list of supported runtimes:
    
        az webapp list-runtimes | grep python
    
    To set latest Python version for an existing app, run the following command:
    
        az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --python-version <VERSION>`,

  references: [
    'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources',
  ],  
  severity: 'high',
}
