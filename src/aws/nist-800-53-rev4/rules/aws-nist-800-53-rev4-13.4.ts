// AWS CIS 1.2.0 Rule equivalent 1.2
export default {
  id: 'aws-nist-800-53-rev4-13.4',  
  title: 'AWS NIST 13.4 IAM users should have MFA (virtual or hardware) enabled',
  
  description: 'Enabling MFA provides increased security as it requires the authenticating principal to possess a device that emits a time-sensitive key (for hardware MFA) and have knowledge of a credential (virtual MFA).',
  
  audit: `Perform the following to determine if IAM users has MFA setup:

  1. Run the following command:

    aws iam get-account-summary | grep "AccountMFAEnabled"

  2. Ensure the AccountMFAEnabled property is set to 1`,
  
  rationale: 'Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.',
  
  remediation: `**Console Remediation Steps**
  
  To enable a virtual MFA device:
  
  - Navigate to [IAM](https://console.aws.amazon.com/iam/).
  - In the navigation pane, choose Users.
  - In the User Name list, choose the name of the intended MFA user.
  - Choose the Security credentials tab. Next to Assigned MFA device, choose Manage.
  - In the Manage MFA Device wizard, choose Virtual MFA device, and then choose Continue. IAM generates and displays configuration information for the virtual MFA device, including a QR code graphic.
  - Open your virtual MFA app. See AWS’s list of supported MFA apps.
  - Determine whether the MFA app supports QR codes, and then do one of the following:
      - From the wizard, choose Show QR code, and then use the app to scan the QR code.
      - In the Manage MFA Device wizard, choose Show secret key, and then type the secret key into your MFA app.
  - In the Manage MFA Device wizard, in the MFA code 1 box, type the one-time password that currently appears in the virtual MFA device. Wait up to 30 seconds for the device to generate a new one-time password. Then type the second one-time password into the MFA code 2 box. Choose Assign MFA.
  
  To enable a hardware MFA device:
  
  - Navigate to [IAM](https://console.aws.amazon.com/iam/).
  - In the navigation bar in the upper right, choose your user name, then My Security Credentials.
  - On the AWS IAM credentials tab, in the Multi-factor authentication section, choose Manage MFA device.
  - In the Manage MFA device wizard, choose Hardware MFA device and then choose Continue.
  - Type the device serial number. The serial number is usually on the back of the device.
  - In the MFA code 1 box, type the six-digit number displayed by the MFA device. You might need to press the button on the front of the device to display the number.
  - Wait 30 seconds while the device refreshes the code, and then type the next six-digit number into the MFA code 2 box. You might need to press the button on the front of the device again to display the second number.
  - Choose Assign MFA.
  
  **CLI Remediation Steps**
  
  To enable a virtual MFA device, you must first create a virtual device entity in IAM to represent a virtual MFA device. Replace MY_MFA_DEVICE_NAME with your desired device name and path/to/QRCode.png with the path where you want the QR code to be saved:,
  
      aws iam create-virtual-mfa-device --virtual-mfa-device-name MY_MFA_DEVICE_NAME --outfile path/to/QRCode.png --bootstrap-method QRCodePNG
  
  To enable a virtual MFA device after creating the entity in IAM, replace MY_USER_NAME with your username, specify the ARN of the virtual MFA device you created, and specify two consecutive codes from the device:
  
      aws iam enable-mfa-device \
          --user-name MY_USER_NAME \
          --serial-number arn:aws:iam::123456789012:mfa/MY_MFA_DEVICE_NAME \
          --authentication-code1 123456 \
          --authentication-code2 789012
  
  To enable a hardware MFA device, replace MY_USER_NAME with your username, specify the serial number of the hardware MFA device, and specify two consecutive codes from the device:
  
      aws iam enable-mfa-device \
          --user-name MY_USER_NAME \
          --serial-number 12345678 \
          --authentication-code1 123456 \
          --authentication-code2 789012`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-iam-user',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cliapi.html',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/create-virtual-mfa-device.html',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/enable-mfa-device.html',
      'https://aws.amazon.com/iam/features/mfa/?audit=2019q1',
  ],
  gql: `{
    queryawsIamUser {
      id
      arn
      accountId
       __typename
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    path: '@.mfaActive',
    equal: true,
  },
}
