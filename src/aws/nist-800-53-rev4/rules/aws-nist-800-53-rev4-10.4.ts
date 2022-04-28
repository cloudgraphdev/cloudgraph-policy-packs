export default {
  id: 'aws-nist-800-53-rev4-10.4',  
  title: 'AWS NIST 10.4 IAM password policies should prevent reuse of the four previously used passwords',
  
  description: 'IAM password policies should prevent users from reusing any of their previous 4 passwords. Preventing password reuse increases account resiliency against brute force login attempts.',
  
  audit: `Perform the following to ensure the password policy is configured as prescribed:
  
  **Via AWS Console**
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Prevent password reuse" is checked
  5. Ensure "Number of passwords to remember" is set to 4
  
  **Via CLI**
  
      aws iam get-account-password-policy
  
  Ensure the output of the above command includes "PasswordReusePrevention": 4`,
  
  rationale: 'Preventing password reuse increases account resiliency against brute force login attempts.',
  
  remediation: `Perform the following to set the password policy as prescribed:
  
  **Via AWS Console**
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Check "Prevent password reuse"
  5. Set "Number of passwords to remember" is set to 4
  
  **Via CLI**
  
      aws iam update-account-password-policy --password-reuse-prevention 4
  
  Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#IAMPasswordPolicy',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html',
  ],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      accountId
       __typename
      passwordReusePrevention
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.passwordReusePrevention',
    equal: 4,
  },
}
