export default {
  id: 'azure-cis-1.3.1-9.10',
  title: 'Azure CIS 9.10 Ensure FTP deployments are disabled',
  relatedRules: ['azure-cis-1.3.1-9.10a', 'azure-cis-1.3.1-9.10b'],
  description:
    'By default, Azure Functions, Web and API Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Service Apps and Functions.',

  audit: `**From Azure Console 2.0 For Web Apps**

  1. Go to the Azure Portal
  2. Select App Services
  3. Click on an App
  4. Select Settings > Configuration
  5. Select General Settings
  6. Under Platform Settings, FTP state should not be All allowed

  **From Azure Console 2.0 For Function Apps**

  1. Go to the Azure Portal
  2. Select App Services
  3. Click on an App Function
  4. Select Platform Features
  5. Select Configuration
  6. Select General Settings
  7. Under Platform Settings, FTP state should not be All allowed

  **Using Azure CLI 2.0**
  List webapps to obtain the ids.

      az webapp list

  List the publish profiles to obtain the username, password and ftp server url.

      az webapp deployment list-publishing-profiles --ids <ids>
      {
          "publishUrl": "ftp://waws-prod-dm1-129.ftp.azurewebsites.windows.net/site/wwwroot",
          "userName": "engineer-webapp-test\\$engineer-webapp-test",
          "userPWD": "dHwjxxxxxxxxxxxxxxxxxxxxxxxxxxisdk6xMgeswoqg",
      }

  The correct username to user for FTP would be engineer-webapp-test in the output above.`,

  rationale:
    'Azure FTP deployment endpoints are public. An attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear-text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.',

  remediation: `From Azure Console

  1. Go to the Azure Portal
  2. Select App Services
  3. Click on an App
  4. Select Settings > Configuration
  5. Under Platform Settings, FTP state should be Disabled or FTPS Only`,

  references: [
    '[Azure Web Service Deploy via FTP](https://docs.microsoft.com/en-us/azure/app-service/deploy-ftp)',
    '[Azure Web Service Deployment](https://docs.microsoft.com/en-us/azure/app-service/overview-security)',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities',
  ],
  severity: 'medium',
}
