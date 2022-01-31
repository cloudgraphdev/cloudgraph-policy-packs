/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.2.0-1.12',
  description: 'GCP CIS 1.12 Ensure API keys are not created for a project',
  audit: `**From Console:**
1. Go to APIs & Services\\Credentials using  https://console.cloud.google.com/apis/credentials
2. In the section API Keys, no API key should be listed.`,
  rationale: `Security risks involved in using API-Keys appear below:

* API keys are simple encrypted strings
* API keys do not identify the user or the application making the API request
* API keys are typically accessible to clients, making it easy to discover and steal an
API key

To avoid the security risk in using API keys, it is recommended to use standard
authentication flow instead.`,
  remediation: `**From Console:**
1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
2. In the section API Keys, to delete API Keys: Click the Delete Bin Icon in front of
  every API Key Name.`,
  references: ['https://cloud.google.com/docs/authentication/api-keys'],
  gql: `{
    querygcpProject {
      id
      __typename
      apiKeys {
        id
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    path: '@.apiKeys',
    isEmpty: true,
  },
}
