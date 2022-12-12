export default {
  id: 'gcp-cis-1.3.0-2.13',
  title:
    'GCP CIS 2.13 Ensure Cloud Asset Inventory Is Enabled',
  description: `GCP Cloud Asset Inventory is services that provides a historical view of GCP resources and
IAM policies through a time-series database. The information recorded includes metadata
on Google Cloud resources, metadata on policies set on Google Cloud projects or resources,
and runtime information gathered within a Google Cloud resource.`,
  audit: `**From Console:

  Ensure that the Cloud Asset API is enabled:**

  1. Go to API & Services/Library by visiting
  https://console.cloud.google.com/apis/library
  2. Search for Cloud Asset API and select the result for Cloud Asset API
  3. Ensure that API Enabled is displayed.

  **From Command Line:

  Ensure that the Cloud Asset API is enabled:**

  1. Query enabled services:

        gcloud services list --enabled --filter=name:cloudasset.googleapis.com

  If the API is listed, then it is enabled. If the response is Listed 0 items the API is not enabled.`,
  rationale: 'The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.',
  remediation: `**From Console:

  Enable the Cloud Asset API:**

  1. Go to API & Services/Library by visiting
    https://console.cloud.google.com/apis/library
  2. Search for Cloud Asset API and select the result for Cloud Asset API
  3. Click the ENABLE button.

  **From Command Line:

  Enable the Cloud Asset API:**

  1. Enable the Cloud Asset API through the services interface:

        gcloud services enable cloudasset.googleapis.com

  **Default Value:**
  
  The Cloud Asset Inventory API is disabled by default in each project
`,
  references: ['https://cloud.google.com/asset-inventory/docs'],
  gql: `{
    querygcpAsset {
      id
      __typename
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  check: ({ resource }: any) => {
    const { assets } = resource
    return !!assets
  },
}
