export default {
  id: 'gcp-cis-1.2.0-1.1',
  description: 'GCP CIS 1.1 Ensure that corporate login credentials are used',
  audit: `For each Google Cloud Platform project, list the accounts that have been granted access to
  that project:
  
      gcloud projects get-iam-policy PROJECT_ID
  
  Also list the accounts added on each folder:
  
      gcloud resource-manager folders get-iam-policy FOLDER_ID
  
  And list your organization's IAM policy:
  
      gcloud organizations get-iam-policy ORGANIZATION_ID
  
  No email accounts outside the organization domain should be granted permissions in the
  IAM policies. This excludes Google-owned service accounts.`,
  rationale: `It is recommended fully-managed corporate Google accounts be used for increased visibility, auditing, and controlling access to Cloud Platform resources. Email accounts based outside of the user's organization, such as personal accounts, should not be used for business purposes.`,
  remediation: `Follow the documentation and setup corporate login accounts.`,
  references: [
    `https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#manage-identities`,
    `https://support.google.com/work/android/answer/`,
    `https://cloud.google.com/sdk/gcloud/reference/organizations/get-iam-policy`,
    `https://cloud.google.com/sdk/gcloud/reference/beta/resource-manager/folders/get-iam-policy`,
    `https://cloud.google.com/sdk/gcloud/reference/projects/get-iam-policy`,
    `https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
    `https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains`,
  ],
  gql: `{
    querygcpOrganization { 
      id 
      __typename
      displayName
      project {
        iamPolicy {
          bindings {
            members
          }
        }
      }
      folder {
        name
        iamPolicy {
          bindings {
            members
          }
        }
      }
    }
  }`,
  resource: 'querygcpOrganization[*]',
  severity: 'medium',
  conditions: {
    jq: `[select((.displayName as $name | .project[].iamPolicy[].bindings[].members[] | contains($name) | not)
    or (.displayName as $name | .folder[].iamPolicy[].bindings[].members[] | contains($name) | not))] 
    | { "match" : (length > 0) }`,
    path: '@',
    and: [
      {
        path: '@.match',
        notEqual: true,
      },
    ],
  },
}
