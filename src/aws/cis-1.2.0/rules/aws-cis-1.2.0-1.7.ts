export default {
  id: 'aws-cis-1.2.0-1.7',
  title: 'AWS CIS 1.7  Ensure IAM password policy requires at least one symbol',
  description: `Password policies are, in part, used to enforce password complexity requirements. IAM
  password policies can be used to ensure password are comprised of different character
  sets. It is recommended that the password policy require at least one symbol.`,
  audit: `Perform the following to ensure the password policy is configured as prescribed:
  Via AWS Console

  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Ensure "Require at least one non-alphanumeric character" is checked under
      "Password Policy"

  Via CLI

    aws iam get-account-password-policy

  Ensure the output of the above command includes "RequireSymbols": true`,
  rationale: `Setting a password complexity policy increases account resiliency against brute force login attempts.`,
  remediation: `Perform the following to set the password policy as prescribed:
  Via AWS Console

  1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
  2. Go to IAM Service on the AWS Console
  3. Click on Account Settings on the Left Pane
  4. Check "Require at least one non-alphanumeric character"
  5. Click "Apply password policy"

  Via CLI

    aws iam update-account-password-policy --require-symbols

  Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.`,
  references: [`CCE- 78905 - 7`],
  gql: `{
    queryawsIamPasswordPolicy {
      id
      arn
      accountId
       __typename
      requireSymbols
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.requireSymbols',
    equal: true,
  },
}
