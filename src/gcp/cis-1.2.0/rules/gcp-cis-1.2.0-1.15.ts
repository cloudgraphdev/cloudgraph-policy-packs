/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.2.0-1.15',
  description: 'GCP CIS 1.15 Ensure API keys are rotated every 90 days',
  audit: `**From Console:**
  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
  2. In the section API Keys, for every key ensure the creation date is less than 90 days.`,
  rationale: `Security risks involved in using API-Keys are listed below:

  * API keys are simple encrypted strings
  * API keys do not identify the user or the application making the API request
  * API keys are typically accessible to clients, making it easy to discover and steal an
  API key

  Because of these potential risks, Google recommends using the standard authentication
  flow instead of API Keys. However, there are limited cases where API keys are more
  appropriate. For example, if there is a mobile application that needs to use the Google
  Cloud Translation API, but doesn't otherwise need a backend server, API keys are the
  simplest way to authenticate to that API.

  Once a key is stolen, it has no expiration, meaning it may be used indefinitely unless the
  project owner revokes or regenerates the key. Rotating API keys will reduce the window of
  opportunity for an access key that is associated with a compromised or terminated account
  to be used.

  API keys should be rotated to ensure that data cannot be accessed with an old key that
  might have been lost, cracked, or stolen.`,
  remediation: `**From Console:**
  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
  2. In the section API Keys, Click the API Key Name. The API Key properties display on a new page.
  3. Click REGENERATE KEY to rotate API key.
  4. Click Save.
  5. Repeat steps 2,3,4 for every API key that has not been rotated in the last 90 days.
  **Note:** Do not set HTTP referrers to wild-cards (* or *.[TLD] or _.[TLD]/_ ) allowing access to
  any/wide HTTP referrer(s)
  Do not set IP addresses and referrer to any host (0.0.0.0 or 0.0.0.0/0 or ::0)`,
  references: ['There is no option to automatically regenerate (rotate) API keys periodically'],
  gql: `{
    querygcpApiKey {
      id
      __typename
      createTime
    }
  }`,
  resource: 'querygcpApiKey[*]',
  severity: 'unknown',
  conditions: {
    value: { daysAgo: {}, path: '@.createTime' },
    lessThan: 90,
  },
}
