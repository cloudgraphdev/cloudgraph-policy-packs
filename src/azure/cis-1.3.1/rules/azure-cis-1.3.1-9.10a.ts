export default {
  id: 'azure-cis-1.3.1-9.10a',
  gql: `{
    queryazureAppServiceWebApp {
      id
      __typename
      siteConfig {
        ftpsState
      }
    }
  }`,
  resource: 'queryazureAppServiceWebApp[*]',
  conditions: {
    not: {
      path: '@.siteConfig.ftpsState',
      equal: 'AllAllowed',
    },
  },
}
