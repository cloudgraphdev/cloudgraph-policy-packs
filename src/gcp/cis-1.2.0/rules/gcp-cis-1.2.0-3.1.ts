export default {
  id: 'gcp-cis-1.2.0-3.1',
  description:
    'GCP CIS 3.1 Ensure that the default network does not exist in a project',
  gql: `{
    querygcpNetwork {
      id
      __typename
      name
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    path: '@.name',
    notEqual: 'default' 
  },
}