// AWS CIS 1.2.0 Rule equivalent 1.13
export default {
  id: 'aws-cis-1.5.0-1.5',  
  title: 'AWS CIS 1.5 Ensure MFA is enabled for the \'root\' user account',
  
  description: `The 'root' user account is the most privileged user in an AWS account. Multi-factor Authentication (MFA) adds an extra layer of protection on top of a username and password. With MFA enabled, when a user signs in to an AWS website, they will be prompted for their username and password as well as for an authentication code from their AWS MFA device.
  
  **Note:** When virtual MFA is used for 'root' accounts, it is recommended that the device used is NOT a personal device, but rather a dedicated mobile device (tablet or phone) that is managed to be kept charged and secured independent of any individual personal devices. ("non-personal virtual MFA") This lessens the risks of losing access to the MFA due to device loss, device trade-in or if the individual owning the device is no longer employed at the company.`,
  
  audit: `Perform the following to determine if the 'root' user account has MFA setup:
  
  **From Command Line:**
  
  1. Run the following command:
  
          aws iam get-account-summary | grep "AccountMFAEnabled"
  
  2. Ensure the AccountMFAEnabled property is set to 1`,
  
  rationale: 'Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.',
  
  remediation: `Perform the following to establish MFA for the 'root' user account:
  
  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  
      Note: to manage MFA devices for the 'root' AWS account, you must use your 'root' account credentials to sign in to AWS. You cannot manage MFA devices for the 'root' account using other credentials.
  
  2. Choose *Dashboard* , and under *Security Status* , expand *Activate MFA* on your root account.
  3. Choose *Activate MFA*
  4. In the wizard, choose *A virtual MFA* device and then choose *Next Step*.
  5. IAM generates and displays configuration information for the virtual MFA device, including a QR code graphic. The graphic is a representation of the 'secret configuration key' that is available for manual entry on devices that do not support QR codes.
  6. Open your virtual MFA application. (For a list of apps that you can use for hosting virtual MFA devices, see [Virtual MFA Applications](https://aws.amazon.com/iam/features/mfa/?audit=2019q1#Virtual_MFA_Applications).) If the virtual MFA application supports multiple accounts (multiple virtual MFA devices), choose the option to create a new account (a new virtual MFA device).
  7. Determine whether the MFA app supports QR codes, and then do one of the following:
      - Use the app to scan the QR code. For example, you might choose the camera icon or choose an option similar to Scan code, and then use the device's camera to scan the code.
      - In the Manage MFA Device wizard, choose Show secret key for manual configuration, and then type the secret configuration key into your MFA application.
  
  When you are finished, the virtual MFA device starts generating one-time passwords. In the Manage MFA Device wizard, in the Authentication Code 1 box, type the one-time password that currently appears in the virtual MFA device. Wait up to 30 seconds for the device to generate a new one-time password. Then type the second one-time password into the Authentication Code 2 box. Choose Active Virtual MFA.`,
  
  references: [
      'CCE-78911-5',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-root',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      name
      mfaActive
    }
  }`,
  exclude: { not: { path: '@.name', equal: 'root' } },
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    path: '@.mfaActive',
    equal: true,
  },
}
