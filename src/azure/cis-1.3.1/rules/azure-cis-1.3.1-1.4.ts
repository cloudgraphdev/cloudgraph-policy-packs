export default {
  id: 'azure-cis-1.3.1-1.4',
  title: 'Azure CIS 1.4 Ensure that \'Allow users to remember multi-factor authentication on devices they trust\' is \'Disabled\' (Manual)',
  description:
    'Do not allow users to remember multi-factor authentication on devices.',
  audit: `**From Azure Console**

  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to All Users
  4. Click on Multi-Factor Authentication button on the top bar
  5. Click on service settings
  6. Ensure that Allow users to remember multi-factor authentication on devices they trust is not enabled

_Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,

  rationale:
    'Remembering Multi-Factor Authentication(MFA) for devices and browsers allows users to have the option to by-pass MFA for a set number of days after performing a successful sign-in using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA.',

  remediation: `**From Azure Console**

  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to All Users
  4. Click on Multi-Factor Authentication button on the top bar
  5. Click on service settings
  6. Disable Allow users to remember multi-factor authentication on devices they trust`,

  references: [
    'https://docs.microsoft.com/en-us/azure/multi-factor-authentication/multi-factor-authentication-whats-next#remember-multi-factor-authentication-for-devices-that-users-trust',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-4-use-strong-authentication-controls-for-all-azure-active-directory-based-access',
  ],
  severity: 'high',
}
