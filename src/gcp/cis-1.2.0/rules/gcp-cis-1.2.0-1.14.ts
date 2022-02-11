export default {
  id: 'gcp-cis-1.2.0-1.14',
  title: 'GCP CIS 1.14 Ensure API keys are restricted to only APIs that application needs access',
  description: `API keys are insecure because they can be viewed publicly, such as from within a browser,
  or they can be accessed on a device where the key resides. It is recommended to restrict
  API keys to use (call) only APIs required by an application.`,
  audit: `**From Console:**
1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
2. In the section API Keys, Click the API Key Name. The API Key properties display on a
new page.
3. For every API Key, ensure the section Key restrictions parameter API
restrictions is not set to None.

Or,
Ensure API restrictions is not set to Google Cloud APIs
Note: Google Cloud APIs represents the API collection of all cloud services/APIs offered
by Google cloud.`,
  remediation: `**From Console:**
1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
2. In the section API Keys, Click the API Key Name. The API Key properties display on a
new page.
3. In the Key restrictions section go to API restrictions.
4. Click the Select API drop-down to choose an API.
5. Click Save.
6. Repeat steps 2,3,4,5 for every unrestricted API key`,
  references: ['https://cloud.google.com/docs/authentication/api-keys', 'https://cloud.google.com/apis/docs/overview'],
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