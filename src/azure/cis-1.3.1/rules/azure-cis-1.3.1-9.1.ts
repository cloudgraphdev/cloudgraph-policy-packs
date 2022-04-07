export default {
  id: 'azure-cis-1.3.1-9.1',  
  title: 'Azure CIS 9.1 Ensure App Service Authentication is set on Azure App Service',
  
  description: 'Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.',
  
  audit: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Authentication / Authorization
  5. Ensure that App Service Authentication set to On
  
  Using Command line:  
  To check App Service Authentication status for an existing app, run the following command,
  
      az webapp auth show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query enabled
  
  The output should return true if App Service authentication is set to On.`,
  
  rationale: 'By Enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider(Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers.',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Go to App Services
  3. Click on each App
  4. Under Setting section, Click on Authentication / Authorization
  5. Set App Service Authentication to On
  6. Choose other parameters as per your requirement and Click on Save
  
  **Using Azure Command Line Interface**  
  To set App Service Authentication for an existing app, run the following command:
  
      az webapp auth update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --enabled true
  
  **Note**  
  In order to access App Service Authentication settings for Web app using Microsoft API requires Website Contributor permission at subscription level. A custom role can be created in place of website contributor to provide more specific permission and maintain the principle of least privileged access.`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/app-service/app-service-authentication-overview',
      'https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#website-contributor',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      authEnabled
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  severity: 'high',
  conditions: {
    path: '@.authEnabled',
    equal: true,
  },
}
