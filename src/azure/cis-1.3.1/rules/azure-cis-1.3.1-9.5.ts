export default {
  id: 'azure-cis-1.3.1-9.5',
  title:
    'Azure CIS 9.5 Ensure that Register with Azure Active Directory is enabled on App Service',

  description:
    'Managed service identity in App Service makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings. When registering with Azure Active Directory in the app service, the app will connect to other Azure services securely without the need of username and passwords.',

  audit: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under the Setting section, Click on Identity
  5. Ensure that Status set to On

  **Using Azure Command Line Interface**
  To check Register with Azure Active Directory feature status for an existing app, run the following command,

      az webapp identity show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query principalId

  The output should return unique Principal ID. If no output for the above command then Register with Azure Active Directory is not set.`,

  rationale:
    'App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.',

  remediation: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Identity
  5. Set Status to On

  **Using Azure Command Line Interface**
  To set Register with Azure Active Directory feature for an existing app, run the following command:

      az webapp identity assign --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME>`,

  references: [
    'https://docs.microsoft.com/en-gb/azure/app-service/app-service-web-tutorial-connect-msi',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-1-standardize-azure-active-directory-as-the-central-identity-and-authentication-system',
  ],
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      siteConfig {
        managedServiceIdentityId
      }
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'medium',
  conditions: {
    path: '@.siteConfig.managedServiceIdentityId',
    isEmpty: false,
  },
}
