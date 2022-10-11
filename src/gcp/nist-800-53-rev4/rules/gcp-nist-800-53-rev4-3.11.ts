export default {
  id: 'gcp-nist-800-53-rev4-3.11',
  title:
    'GCP NIST 3.11  IAM default audit log config should include \'DATA_READ\' and \'DATA_WRITE\' log types',
  description: 
    'A best practice is to enable \'DATA_READ\' and \'DATA_WRITE\' data access log types as part of the default IAM audit log config, so that read and write operations on user-provided data are tracked across all relevant services. Please note that the \'ADMIN_WRITE\' log type and BigQuery data access logs are enabled by default.',

  audit: '',
  rationale: '',
  remediation: `**From Console:**

  1. Navigate to IAM & Admin, Audit Logs, or using https://console.cloud.google.com/iam-admin/audit
  2. Click on Set Default Configuration at the top of the page.
  34. In the Log Type tab, select the Data Write and Data Read boxes.
  4. Click Save.

  **From Command Line:**
  1. Run the following command to read the project’s IAM policy:

      gcloud projects get-iam-policy PROJECT_ID > /tmp/project_policy.yaml
  
  2. Alternatively, the policy can be set at the organization or folder level. If setting the policy at the organization level, it is not necessary to also set it for each folder or project.

      gcloud organizations get-iam-policy ORGANIZATION_ID > /tmp/org_policy.yaml
      gcloud resource-manager folders get-iam-policy FOLDER_ID > /tmp/folder_policy.yaml

  3. Edit policy in /tmp/policy.yaml, adding or changing only the audit logs configuration to:

      auditConfigs:
      - auditLogConfigs:
        - logType: DATA_WRITE
        - logType: DATA_READ
        service: allServices

  4. To write new IAM policy run the following command:

      gcloud organizations set-iam-policy ORGANIZATION_ID /tmp/org_policy.yaml
      gcloud resource-manager folders set-iam-policy FOLDER_ID /tmp/folder_policy.yaml
      gcloud projects set-iam-policy PROJECT_ID /tmp/project_policy.yaml
  `,
  references: [
    'https://cloud.google.com/logging/docs/audit/',
    'https://cloud.google.com/logging/docs/audit/configure-data-access',
    'https://cloud.google.com/sdk/gcloud/reference/projects/get-iam-policy',
  ],
  gql: `{
    querygcpIamPolicy{
      id
      __typename
      auditConfigs {
        auditLogConfigs {
          logType
        }
      }
    }
  }`,
  resource: 'querygcpIamPolicy[*]',
  severity: 'medium',
  conditions: {
    path: '@.auditConfigs',
    array_all: {
      and: [
        {
          path: '[*].auditLogConfigs',
          array_any: {
            path: '[*].logType',
            equal: 'DATA_WRITE',
          },
        },
        {
          path: '[*].auditLogConfigs',
          array_any: {
            path: '[*].logType',
            equal: 'DATA_READ',
          },
        },
      ],
    },
  },
}
