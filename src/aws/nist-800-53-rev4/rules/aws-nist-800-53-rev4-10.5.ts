// AWS CIS 1.2.0 Rule equivalent 1.6
export default {
  id: 'aws-nist-800-53-rev4-10.5',  
  title: 'AWS NIST 10.5 IAM password policies should require at least one lowercase character',
  
  description: `Password policies are, in part, used to enforce password complexity requirements. IAM
  password policies can be used to ensure password are comprised of different character
  sets. It is recommended that the password policy require at least one lowercase letter.`,

  audit: `Perform the following to ensure the password policy is configured as prescribed:
  Via the AWS Console

  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Requires at least one lowercase letter" is checked under "Password Policy"

  Via CLI

    aws iam get-account-password-policy

  Ensure the output of the above command includes "RequireLowercaseCharacters": true`,

  rationale: 'Setting a password complexity policy increases account resiliency against brute force login attempts.',

  remediation: `Perform the following to set the password policy as prescribed:
  Via the AWS Console

  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Check "Requires at least one lowercase letter"
  5. Click "Apply password policy"

  Via CLI

    aws iam update-account-password-policy --require-lowercase-characters

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
      requireLowercaseCharacters
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.requireLowercaseCharacters',
    equal: true,
  },
}
