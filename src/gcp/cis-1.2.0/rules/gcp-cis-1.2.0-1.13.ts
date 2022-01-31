/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.2.0-1.13',
  description:
    'GCP CIS 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps',
  audit: `**From Console:**
  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
  2. In the section API Keys, Click the API Key Name. The API Key properties display on a
    new page.
  3. For every API Key, ensure the section Key restrictions parameter Application
    restrictions is not set to None.
  
      Or,

      Ensure Application restrictions is set to HTTP referrers and the referrer is not set to
      wild-cards (* or *.[TLD] or *.[TLD]/*) allowing access to any/wide HTTP
      referrer(s)

      Or,

      Ensure Application restrictions is set to IP addresses and referrer is not set to any
      host (0.0.0.0 or 0.0.0.0/0 or ::0)`,
  rationale: `Security risks involved in using API-Keys appear below:

  * API keys are simple encrypted strings
  * API keys do not identify the user or the application making the API request
  * API keys are typically accessible to clients, making it easy to discover and steal an
  API key

  In light of these potential risks, Google recommends using the standard authentication flow
  instead of API keys. However, there are limited cases where API keys are more appropriate.
  For example, if there is a mobile application that needs to use the Google Cloud Translation
  API, but doesn't otherwise need a backend server, API keys are the simplest way to
  authenticate to that API.

  In order to reduce attack vectors, API-Keys can be restricted only to trusted hosts, HTTP
  referrers and applications.`,
  remediation: `**From Console:**
1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
2. In the section API Keys, Click the API Key Name. The API Key properties display on a
  new page.
3. In the Key restrictions section, set the application restrictions to any of HTTP
  referrers, IP Adresses, Android Apps, iOs Apps.
4. Click Save.
5. Repeat steps 2,3,4 for every unrestricted API key.
  **Note:** Do not set HTTP referrers to wild-cards (* or *.[TLD] or _.[TLD]/_ ) allowing
  access to any/wide HTTP referrer(s)
  Do not set IP addresses and referrer to any host (0.0.0.0 or 0.0.0.0/0 or ::0)`,
  references: ['https://cloud.google.com/docs/authentication/api-keys'],
  gql: `{
    querygcpApiKey {
      id
      __typename
      restrictions{
        browserKeyRestrictions{
          allowedReferrers
        }
        serverKeyRestrictions{
          allowedIps
        }
        androidKeyRestrictions{
          allowedApplications{
            packageName
          }
        }
        iosKeyRestrictions{
          allowedBundleIds
        }
      }
    }
  }`,
  resource: 'querygcpApiKey[*]',
  severity: 'unknown',
  conditions: {
    or: [
      {
        path: '@.androidKeyRestrictions.allowedApplications',
        isEmpty: false,
      },
      {
        path: '@.iosKeyRestrictions.allowedBundleIds',
        isEmpty: false,
      },
      {
        and: [
          {
            path: '@.browserKeyRestrictions.allowedReferrers',
            isEmpty: false,
          },
          {
            path: '@.browserKeyRestrictions.allowedReferrers',
            array_all: {
              path: '[*]',
              mismatch: /^(\*|\*\.\w+|\*\.\w+\/\*)$/,
            },
          },
        ],
      },
      {
        and: [
          {
            path: '@.serverKeyRestrictions.allowedIps',
            isEmpty: false,
          },
          {
            path: '@.serverKeyRestrictions.allowedIps',
            array_all: {
              path: '[*]',
              notIn: ['0.0.0.0', '0.0.0.0/0', '::0'],
            },
          },
        ],
      },
    ],
  },
}
