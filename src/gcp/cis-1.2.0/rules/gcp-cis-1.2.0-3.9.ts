export default {
  id: 'gcp-cis-1.2.0-3.9',
  description:
    'GCP CIS 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites',
  gql: `{
    querygcpProject{
      id
      projectId
      __typename
      targetHttpsProxies{
        id
        name
        sslPolicy
      }
      targetSslProxies{
        id
        name
        sslPolicy
      }
      sslPolicies{
        profile
        enabledFeatures
        minTlsVersion
        selfLink
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    path: '@',
    jq: `{
      "id": .id,
      "targetHttpsProxiesAndTargetSslProxies" : (
        [(.targetHttpsProxies + .targetSslProxies)[] + {"targetSslPolicy" :  .sslPolicies }]
        | map(. as $proxy | ($proxy.targetSslPolicy |= (select($proxy.sslPolicy == $proxy.targetSslPolicy[].selfLink) // null )[0]) )
        )
    }
    `,
    and: [
      {
        path: '@.targetHttpsProxiesAndTargetSslProxies',
        array_all: {
          and: [
            {
              path: '[*].targetSslPolicy',
              notEqual: null,
            },
            {
              path: '[*].targetSslPolicy',
              or: [
                {
                  and: [
                    {
                      path: '[*].profile',
                      equal: 'MODERN',
                    },
                    {
                      path: '[*].minTlsVersion',
                      equal: 'TLS_1_2',
                    },
                  ],
                },
                {
                  and: [
                    {
                      path: '[*].profile',
                      equal: 'RESTRICTED',
                    },
                  ],
                },
                {
                  and: [
                    {
                      path: '[*].profile',
                      equal: 'CUSTOM',
                    },
                    {
                      path: '[*].enabledFeatures',
                      array_all: {
                        path: '[*]',
                        notIn: [
                          'TLS_RSA_WITH_AES_128_GCM_SHA256',
                          'TLS_RSA_WITH_AES_256_GCM_SHA384',
                          'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                        ],
                      },
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
    ],
  },
}
