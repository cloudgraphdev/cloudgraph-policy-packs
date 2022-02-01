export default {
  id: 'aws-cis-1.2.0-1.8',
  description:
    'AWS CIS 1.8  Ensure IAM password policy requires at least one number',
  audit: `Perform the following to ensure the password policy is configured as prescribed:  
  Via AWS Console
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Require at least one number " is checked under "Password Policy"
  
  Via CLI

    aws iam get-account-password-policy
  
  Ensure the output of the above command includes "RequireNumbers": true`,
  rationale: `Setting a password complexity policy increases account resiliency against brute force login attempts.`,
  remediation: `Perform the following to set the password policy as prescribed:  
  Via AWS Console
  
  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Check "Require at least one number"
  5. Click "Apply password policy"
  
  
  Via CLI

    aws iam update-account-password-policy --require-numbers
  
  Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.`,
  references: [`CCE- 78906 - 5`],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireNumbers
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.requireNumbers',
    equal: true,
  },
}
