export default {
  id: 'aws-nist-800-53-rev4-10.1',  
  title: 'AWS NIST 10.1 IAM password policies should expire passwords within 90 days',
  
  description: 'IAM password policies can require passwords to be rotated or expired after a given number of days. Reducing the password lifetime increases account resiliency against brute force login attempts.',
  
  audit: `Perform the following to ensure the password policy is configured as prescribed:
  Via AWS Console
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Expire passwords in" is set to 90 day(s).
  
  Via CLI
  
  aws iam get-account-password-policy
  
  Ensure the output of the above command includes "maxPasswordAge": 90`,
  
  rationale: 'Setting a password complexity policy increases account resiliency against brute force login attempts.',
  
  remediation: `**AWS Console**
  
  - Navigate to [IAM](https://console.aws.amazon.com/iam).
  - In the left navigation, select Account settings.
  - Check the Enable password expiration checkbox.
  - In the Password expiration period (days) field, enter 90 days or less.
  - Click the Apply password policy button.
  
  **AWS CLI**
  
  Set IAM password policy to expire passwords in 90 days.
  
  This operation does not support partial updates. No parameters are required, but if you do not specify a parameter, that parameter’s value reverts to its default value.
  
      aws iam update-account-password-policy <other password options> --max-password-age 90`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#IAMPasswordPolicy',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html',
  ],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      accountId
       __typename
      expirePasswords
      maxPasswordAge
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    and: [
     {
        path: '@.expirePasswords',
        equal: true,
     },
     {
        path: '@.maxPasswordAge',
        lessThanInclusive: 90,
     },
    ] 
  },
}
