export default {
  id: 'gcp-cis-1.2.0-1.1',
  description: 'GCP CIS 1.1 Ensure that corporate login credentials are used',
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
