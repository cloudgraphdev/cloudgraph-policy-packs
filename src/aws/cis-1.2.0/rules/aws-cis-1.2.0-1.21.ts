/* eslint-disable max-len */
export default {
  id: 'aws-cis-1.2.0-1.21',
  title:
    'AWS CIS 1.21 Do not setup access keys during initial user setup for all IAM users that have a console password',
  description:
    'AWS console defaults the checkbox for creating access keys to enabled. This results in many access keys being generated unnecessarily. In addition to unnecessary credentials, it also generates unnecessary management work in auditing and rotating these keys.',
  audit: `Perform the following to determine if access keys are rotated as prescribed:

  1. Login to the AWS Management Console
  2. Click Services
  3. Click IAM
  4. Click on a User
  5. Compare the user creation date to the key 1 creation date.
  6. For any that match, the key was created during initial user setup.

  - Keys that were created at the same time as the user profile and do not have a last used date should be deleted.

  Via the CLI

  1. Run the following command (OSX/Linux/UNIX) to generate a list of all IAM users along with their access keys utilization:

          aws iam generate-credential-report

          aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,9,11,14,16

  2. The output of this command will produce a table similar to the following:

          user,password_enabled,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
              elise,false,true,2015-04-16T15:14:00+00:00,false,N/A
              brandon,true,true,N/A,false,N/A
              rakesh,false,false,N/A,false,N/A
              helene,false,true,2015-11-18T17:47:00+00:00,false,N/A
              paras,true,true,2016-08-28T12:04:00+00:00,true,2016-03-04T10:11:00+00:00
              anitha,true,true,2016-06-08T11:43:00+00:00,true,N/A

  3. For any user having access_key_last_used_date set to N/A , ensure that access key is deleted .`,

  rationale: `Requiring that additional steps be taken by the user after their profile has been created will give a stronger indication of intent that access keys are [a] necessary for their work and [b] once the access key is established on an account that the keys may be in use somewhere in the organization.

  **Note**: Even if it is known the user will need access keys, require them to create the keys themselves or put in a support ticket to have the created as a separate step from user creation.`,

  remediation: `Perform the following to delete access keys that do not pass the audit:

  1. Login to the AWS Management Console:
  2. Click Services
  3. Click IAM
  4. Click on Users
  5. Click on Security Credentials
  6. As an Administrator

  - Click on Delete for keys that were created at the same time as the user profile but have not been used.

  7. As an IAM User

  - Click on Delete for keys that were created at the same time as the user profile but have not been used.

  Via CLI

      aws iam delete-access-key

  **Notes**:
  Credential report does not appear to contain "Key Creation Date" - maybe a feature request to AWS?`,

  references: [],
  gql: `{
    queryawsIamPolicy {
      id
      arn
      accountId
       __typename
      iamUsers {
        accessKeyData {
          lastUsedDate
        }
      }
    }
  }`,
  resource: 'queryawsIamPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.iamUsers',
    array_any: {
      path: '[*].accessKeyData',
      array_any: {
        path: '[*].lastUsedDate',
        notIn: [null, 'N/A', ''],
      },
    },
  },
}
