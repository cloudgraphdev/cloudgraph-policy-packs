// AWS CIS 1.2.0 Rule equivalent 1.20
export default {
  id: 'aws-cis-1.5.0-1.17',  
  title: 'AWS CIS 1.17 Ensure a support role has been created to manage incidents with AWS Support',
  
  description: 'AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support.',
  
  audit: `**From Command Line:**
  
  1. List IAM policies, filter for the 'AWSSupportAccess' managed policy, and note the "Arn" element value:
  
          aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"
  
  2. Check if the 'AWSSupportAccess' policy is attached to any role:
  
          aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess
  
  3. In Output, Ensure PolicyRoles does not return empty. 'Example: Example: PolicyRoles: [ ]'
  
  If it returns empty refer to the remediation below.`,
  
  rationale: 'By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.',
  
  remediation: `**From Command Line:**
  
  1. Create an IAM role for managing incidents with AWS:
  
  - Create a trust relationship policy document that allows <iam_user> to manage AWS incidents, and save it locally as /tmp/TrustPolicy.json:
  
          { 
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Effect": "Allow",
                      "Principal": {
                          "AWS": "<iam_user>" 
                       },
                      "Action": "sts:AssumeRole"
                  }
              ] 
          }
  
  2. Create the IAM role using the above trust policy:
  
          aws iam create-role --role-name <aws_support_iam_role> --assume-role-policy-document file:///tmp/TrustPolicy.json
  
  3. Attach 'AWSSupportAccess' managed policy to the created IAM role:
  
          aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name <aws_support_iam_role>`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html',
      'https://aws.amazon.com/premiumsupport/pricing/',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html',
  ],
  gql: `{
    queryawsAccount { 
      id
      __typename
      iamPolicies {
         name
         iamUsers {
           arn
         }
         iamGroups {
           arn
         }
         iamRoles {
           arn
         }
       }
     }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.iamPolicies',
    array_any: {
      and: [
       {
        path: '[*].name',
        equal: 'AWSSupportAccess',
       },
       {
        or: [
          {
            path: '[*].iamUsers',
            isEmpty: false,
          },
          {
            path: '[*].iamGroups',
            isEmpty: false,
          },
          {
            path: '[*].iamRoles',
            isEmpty: false,
          },
        ],
       },
      ],
    },
  },
}
