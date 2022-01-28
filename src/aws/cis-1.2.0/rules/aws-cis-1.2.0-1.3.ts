export default {
  id: 'aws-cis-1.2.0-1.3',
  description:
    'AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled',
  audit: `Perform the following to determine if unused credentials exist:
  **Download Credential Report:**
  Using Management Console:
  
  1. Login to the AWS Management Console
  2. Click Services
  3. Click IAM
  4. Click on Credential Report
  5. This will download an .xls file which contains credential usage for all users within an AWS Account - open this file
  
  Via CLI
  
  1. Run the following commands:
  
  aws iam generate-credential-report
  
  aws iam get-credential-report --query 'Content' --output text | base64 -d |
  cut -d, -f1,4,5,6,9,10,11,14,15,
  
  **Ensure unused credentials does not exist:**
  
  
  2. For each user having password_enabled set to TRUE, ensure password_last_used_date is less than 90 days ago.
  
  \`\`\`
  When password_enabled is set to TRUE and password_last_used is set to No_Information , ensure password_last_changed is less than 90 days ago.
  \`\`\`

  3. For each user having an access_key_1_active or access_key_2_active to TRUE, ensure the corresponding access_key_n_last_used_date is less than 90 days ago.
  
  \`\`\`
  When a user having an access_key_x_active (where x is 1 or 2) to TRUE and corresponding access_key_x_last_used_date is set to N/A', ensureaccess_key_x_last_rotated is less than 90 days ago.
  \`\`\``,
  rationale: `Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used.`,
  remediation: `Perform the following to remove or deactivate credentials:

  1. Login to the AWS Management Console:
  2. Click Services
  3. Click IAM
  4. Click on Users
  5. Click on Security Credentials
  6. As an Administrator
  
  \`\`\`
  Click on Make Inactive for credentials that have not been used in 90 Days
  \`\`\`
  
  7. As an IAM User
  
  \`\`\`
  Click on Make Inactive or Delete for credentials which have not been used in 90 Days
  \`\`\``,
  references: [],
  gql: `{
   queryawsIamUser {
      id
      __typename
      passwordLastUsed
      accessKeyData {
        lastUsedDate
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        value: { daysAgo: {}, path: '@.passwordLastUsed' },
        lessThanInclusive: 90,
      },
      {
        path: '@.accessKeyData',
        array_any: {
          value: { daysAgo: {}, path: '[*].lastUsedDate' },
          lessThanInclusive: 90,
        },
      },
    ],
  },
}
