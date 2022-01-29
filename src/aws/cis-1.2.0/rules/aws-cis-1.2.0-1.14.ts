export default {
  id: 'aws-cis-1.2.0-1.14',
  description:
    "AWS CIS 1.14 Ensure hardware MFA is enabled for the 'root' account (Scored)",
  audit: `Perform the following to determine if the root account has a hardware MFA setup:

  1. Run the following command to determine if the root account has MFA setup:
  
    aws iam get-account-summary | grep "AccountMFAEnabled"
  
  The *AccountMFAEnabled* property is set to 1 will ensure that the root account has MFA (Virtual or Hardware) Enabled.  
  If *AccountMFAEnabled* property is set to 0 the account is not compliant with this recommendation.
  
  <br/>

  2. If *AccountMFAEnabled* property is set to 1, determine root account has Hardware MFA enabled. Run the following command to list all virtual MFA devices:
  
    aws iam list-virtual-mfa-devices
  
  If the output contains one MFA with the following Serial Number, it means the MFA is virtual, not hardware and the account is not compliant with this recommendation: *"SerialNumber": "arn:aws:iam::_<aws_account_number>_:mfa/root-account-mfa-device"*`,
  rationale: `A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA does not suffer the attack surface introduced by the mobile smartphone on which a virtual MFA resides.

  **Note**: Using hardware MFA for many, many AWS accounts may create a logistical device management issue. If this is the case, consider implementing this Level 2 recommendation selectively to the highest security AWS accounts and the Level 1 recommendation applied to the remaining accounts.
  
  Link to order AWS compatible hardware MFA device: [http://onlinenoram.gemalto.com/](http://onlinenoram.gemalto.com/)`,
  remediation: `Perform the following to establish a hardware MFA for the root account:

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  
  Note: to manage MFA devices for the root AWS account, you must use your root account credentials to sign in to AWS. You cannot manage MFA devices for the root account using other credentials.
  
  2. Choose *Dashboard* , and under *Security Status* , expand *Activate MFA* on your root account.
  3. Choose *Activate MFA*
  4. In the wizard, choose *A hardware MFA* device and then choose *Next Step*.
  5. In the *Serial Number* box, enter the serial number that is found on the back of the MFA device.
  6. In the *Authentication Code 1* box, enter the six-digit number displayed by the MFA device. You might need to press the button on the front of the device to display the number.
  7. Wait 30 seconds while the device refreshes the code, and then enter the next six-digit number into the *Authentication Code 2* box. You might need to press the button on the front of the device again to display the second number.
  8. Choose *Next Step*. The MFA device is now associated with the AWS account. The next time you use your AWS account credentials to sign in, you must type a code from the hardware MFA device.`,
  references: [
    `CCE- 78911 - 5`,
    `CIS CSC v6.0 #5.6, #11.4, #12.6, #16.11`,
    `Order Hardware MFA: http://onlinenoram.gemalto.com/`,
    `http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html`,
    `http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html#enable-hw-mfa-for-root`,
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      name
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
