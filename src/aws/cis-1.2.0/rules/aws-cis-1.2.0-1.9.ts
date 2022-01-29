export default {
  id: 'aws-cis-1.2.0-1.9',
  description:
    'AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater',
  audit: `Perform the following to ensure the password policy is configured as prescribed:  
  Via AWS Console
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Minimum password length" is set to 14 or greater.
  
  Via CLI

    aws iam get-account-password-policy
  
  Ensure the output of the above command includes "MinimumPasswordLength": 14 (or higher)`,
  rationale: `Setting a password complexity policy increases account resiliency against brute force login attempts.`,
  remediation: `Perform the following to set the password policy as prescribed:  
  Via AWS Console
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Set "Minimum password length" to 14 or greater.
  5. Click "Apply password policy"
  
  Via CLI

    aws iam update-account-password-policy --minimum-password-length 14
  
  Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.`,
  references: [`CCE- 78907 - 3`, `CIS CSC v6.0 #5.7, #16.12`],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      minimumPasswordLength
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.minimumPasswordLength',
    greaterThanInclusive: 14,
  },
}
