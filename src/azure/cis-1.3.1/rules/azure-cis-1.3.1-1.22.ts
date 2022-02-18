export default {
  id: 'azure-cis-1.3.1-1.22',  
  title: 'Azure CIS 1.22 Ensure Security Defaults is enabled on Azure Active Directory',  
  
  description: `Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks.
  
  Microsoft is making security defaults available to everyone. The goal is to ensure that all organizations have a basic level of security-enabled at no extra cost. You turn on security defaults in the Azure portal.`,
  
  audit: `**From Azure Console**  
  To ensure security defaults is enabled in your directory:
  
  1. Sign in to the Azure portal as a security administrator, Conditional Access administrator, or global administrator.
  2. Browse to Azure Active Directory > Properties.
  3. Select Manage security defaults.
  4. Verify the Enable security defaults toggle to Yes.`,
  
  rationale: `Security defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.
  
  For example doing the following:
  
  - Requiring all users and admins to register for MFA.
  - Challenging users with MFA - mostly when they show up on a new device or app, but more often for critical roles and tasks.
  - Disabling authentication from legacy authentication clients, which can’t do MFA.`,  
  
  remediation: `**From Azure Console**  
  To enable security defaults in your directory:
  
  1. Sign in to the Azure portal as a security administrator, Conditional Access administrator, or global administrator.
  2. Browse to Azure Active Directory > Properties.
  3. Select Manage security defaults.
  4. Set the Enable security defaults toggle to Yes.
  5. Select Save.`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults',
      'https://techcommunity.microsoft.com/t5/azure-active-directory-identity/introducing-security-defaults/ba-p/1061414',
  ],    
  gql: `{
    queryazureAdIdentitySecurityDefaultsEnforcementPolicy {
      id
      __typename
      isEnabled
    }
  }`,
  resource: 'queryazureAdIdentitySecurityDefaultsEnforcementPolicy[*]',
  severity: 'high',
  conditions: {
    path: '@.isEnabled',
    equal: true,
  },
}
