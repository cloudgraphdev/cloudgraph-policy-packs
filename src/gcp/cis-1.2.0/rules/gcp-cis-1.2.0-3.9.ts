export default {
  id: 'gcp-cis-1.2.0-3.9',
  description:
    'GCP CIS 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites',
  audit: `**From Console:**

  1. See all load balancers by visiting https://console.cloud.google.com/net-services/loadbalancing/loadBalancers/list.
  2. For each load balancer for *SSL (Proxy)* or *HTTPS*, click on its name to go the *Load balancer details* page.
  3. Ensure that each target proxy entry in the *Frontend* table has an *SSL Policy* configured.
  4. Click on each SSL policy to go to its *SSL policy details* page.
  5. Ensure that the SSL policy satisfies one of the following conditions:
  
  
  - has a *Min TLS* set to *TLS 1.2* and *Profile* set to *Modern* profile, or
  - has *Profile* set to *Restricted*. Note that a Restricted profile effectively requires
  clients to use TLS 1.2 regardless of the chosen minimum TLS version, or
  - has *Profile* set to *Custom* and the following features are all disabled:
  
          TLS_RSA_WITH_AES_128_GCM_SHA256
          TLS_RSA_WITH_AES_256_GCM_SHA384
          TLS_RSA_WITH_AES_128_CBC_SHA
          TLS_RSA_WITH_AES_256_CBC_SHA
          TLS_RSA_WITH_3DES_EDE_CBC_SHA
  
  **From Command Line:**
  
  1. List all TargetHttpsProxies and TargetSslProxies.
  
          gcloud compute target-https-proxies list
          gcloud compute target-ssl-proxies list
  
  2. For each target proxy, list its properties:
  
          gcloud compute target-https-proxies describe TARGET_HTTPS_PROXY_NAME
          gcloud compute target-ssl-proxies describe TARGET_SSL_PROXY_NAME
  
  3. Ensure that the *sslPolicy* field is present and identifies the name of the SSL policy:
  
          sslPolicy: https://www.googleapis.com/compute/v1/projects/PROJECT_ID/global/sslPolicies/SSL_POLICY_NAME
  
  If the *sslPolicy* field is missing from the configuration, it means that the GCP default policy is used, which is insecure.
  
  4. Describe the SSL policy:
  
          gcloud compute ssl-policies describe SSL_POLICY_NAME
  
  5. Ensure that the policy satisfies one of the following conditions:
  
  - has *Profile* set to *Modern* and *minTlsVersion* set to *TLS_1_2*, or
  - has *Profile* set to *Restricted*, or
  - has *Profile* set to *Custom* and *enabledFeatures* does not contain any of the following values:
  
          TLS_RSA_WITH_AES_128_GCM_SHA256
          TLS_RSA_WITH_AES_256_GCM_SHA384
          TLS_RSA_WITH_AES_128_CBC_SHA
          TLS_RSA_WITH_AES_256_CBC_SHA
          TLS_RSA_WITH_3DES_EDE_CBC_SHA`,
  rationale: `Load balancers are used to efficiently distribute traffic across multiple servers. Both SSL proxy and HTTPS load balancers are external load balancers, meaning they distribute traffic from the Internet to a GCP network. GCP customers can configure load balancer SSL policies with a minimum TLS version (1.0, 1.1, or 1.2) that clients can use to establish a connection, along with a profile (Compatible, Modern, Restricted, or Custom) that specifies permissible cipher suites. To comply with users using outdated protocols, GCP load balancers can be configured to permit insecure cipher suites. In fact, the GCP default SSL policy uses a minimum TLS version of 1.0 and a Compatible profile, which allows the widest range of insecure cipher suites. As a result, it is easy for customers to configure a load balancer without even knowing that they are permitting outdated cipher suites.`,
  remediation: `**From Console:**  
  If the TargetSSLProxy or TargetHttpsProxy does not have an SSL policy configured, create a new SSL policy. Otherwise, modify the existing insecure policy.
  
  1. Navigate to the *SSL Policies* page by visiting: https://console.cloud.google.com/net-security/sslpolicies
  2. Click on the name of the insecure policy to go to its *SSL policy details* page.
  3. Click *EDIT*.
  4. Set *Minimum TLS version* to *TLS 1.2*.
  5. Set *Profile* to *Modern* or *Restricted*.
  6. Alternatively, if teh user selects the profile *Custom*, make sure that the following features are disabled:
  
          TLS_RSA_WITH_AES_128_GCM_SHA256
          TLS_RSA_WITH_AES_256_GCM_SHA384
          TLS_RSA_WITH_AES_128_CBC_SHA
          TLS_RSA_WITH_AES_256_CBC_SHA
          TLS_RSA_WITH_3DES_EDE_CBC_SHA
  
  **From Command Line:**
  
  1. For each insecure SSL policy, update it to use secure cyphers:
  
          gcloud compute ssl-policies update NAME [--profile COMPATIBLE|MODERN|RESTRICTED|CUSTOM] --min-tls-version 1.2 [--custom-features FEATURES]
  
  
  2. If the target proxy has a GCP default SSL policy, use the following command corresponding to the proxy type to update it.
  
          gcloud compute target-ssl-proxies update TARGET_SSL_PROXY_NAME --ssl-policy SSL_POLICY_NAME
          gcloud compute target-https-proxies update TARGET_HTTPS_POLICY_NAME --ssl- policy SSL_POLICY_NAME
  `,
  references: [
    `https://cloud.google.com/load-balancing/docs/use-ssl-policies`,
    `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf`,
  ],
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
