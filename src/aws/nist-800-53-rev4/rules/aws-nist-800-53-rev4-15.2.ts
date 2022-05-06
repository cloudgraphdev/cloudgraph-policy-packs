export default {
  id: 'aws-nist-800-53-rev4-15.2',  
  title: 'AWS NIST 15.2 IAM roles used for trust relationships should have MFA or external IDs',
  
  description: `IAM roles that establish trust with other AWS accounts should use additional security measures such as MFA or external IDs. This can protect your account if the trusted account is compromised and can also prevent the “confused deputy problem.”
  
  NOTE: This rule only evaluates statements with the **sts:AssumeRole** action.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  Enable MFA
  
  - Log into the AWS Management Console.
  - From the top navigation, select your Account Name > My Security Credentials.
  - In the top navigation, select the Trust Relationships tab.
  - Expand the Multi-factor authentication (MFA) drop-down, select Active MFA.
  - Open your virtual MFA application, scan the QR code.
  - Enter the two codes that are generated from your virtual MFA.
  - Click Assign.
  
  Add an External ID
  
  - Navigate to [IAM](https://console.aws.amazon.com/iam/).
  - Select Roles and select the desired IAM role.
  - In the top navigation, select the Trust Relationships tab.
  - Click Edit trust relationship.
  - In "Conditions", add the following: "Condition": {"StringEquals": {"sts:ExternalId": "Unique ID Assigned by Example Corp"}}.
  - Click Update Trust Policy.
  
  **AWS CLI**
  
  Enable MFA
  
  Enable MFA via the CLI.
  
      create-virtual-mfa-device
  
      --path <value>
  
      --virtual-mfa-device-name <value>
  
      --outfile <value>
  
      --bootstrap-method <value>
  
  Add an External ID
  
  Add an external ID to your IAM role.
  
      update-assume-role-policy
  
      --policy-document (string)`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cliapi.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/update-assume-role-policy.html',
  ],
  gql: `{
    queryawsIamRole {
      id
      arn
      accountId
      __typename
      assumeRolePolicy {
        statement {
          condition {
            key
            value
          }
        }
      }
    }
  }`,
  resource: 'queryawsIamRole[*]',
  severity: 'high',
  conditions: {
    path: '@.assumeRolePolicy.statement',
    array_any: {
      path: '[*].condition',
      array_any: {
        and: [
          {
            path: '[*].key',
            equal: 'sts:ExternalId',
          },
          {
            path: '[*].value',
            isEmpty: false,
          },
        ],
      },
    },
  },
}
