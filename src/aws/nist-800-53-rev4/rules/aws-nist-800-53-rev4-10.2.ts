export default {
  id: 'aws-nist-800-53-rev4-10.2',  
  title: 'AWS NIST 10.2 IAM password policies should have a minimum length of 7 and include both alphabetic and numeric characters',
  
  description: 'IAM password policies are used to enforce password complexity requirements and increase account resiliency against brute force login attempts. Password policies should require passwords to be at least 7 characters long and include both alphabetic and numeric characters.',
  
  audit: `Perform the following to ensure the password policy is configured as prescribed:
  
  **Via AWS Console**
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Minimum password length" is set to 7 or greater
  5. Ensure "Require at least one number " is checked under "Password Policy"
  
  **Via CLI**
  
  aws iam get-account-password-policy
  
  Ensure the output of the above command includes "MinimumPasswordLength": 14 (or higher)`,
  
  rationale: 'Setting a password complexity policy increases account resiliency against brute force login attempts.',
  
  remediation: `**AWS Console**
  
  - Navigate to Identity and Access Management.
  - In the left navigation, select Account Settings.
  - In the Minimum password length field, enter 7.
  - Check Require at least one number.
  - Click Apply password policy.
  
  **AWS CLI**
  
  Set password policy to have a minimum length of 7 and include both alphabetic and numeric characters.
  
  This operation does not support partial updates. No parameters are required, but if you do not specify a parameter, that parameter’s value reverts to its default value.
  
      aws iam update-account-password-policy <other password options> --require-numbers --minimum-password-length 7`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#IAMPasswordPolicy',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html',
  ],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      accountId
       __typename
      minimumPasswordLength
      requireNumbers
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.minimumPasswordLength',
        greaterThanInclusive: 7,
      },
      {
        path: '@.requireNumbers',
        equal: true,
      },
    ]
  },
}
