export default {
  id: 'azure-cis-1.3.1-9.10b',
  gql: `{
    queryazureFunctionApp {
      id
      __typename
      siteConfig {
        ftpsState
      }
    }
  }`,
  resource: 'queryazureFunctionApp[*]',
  conditions: {
    not: {
      path: '@.siteConfig.ftpsState',
      equal: 'AllAllowed',
    },
  },
}
