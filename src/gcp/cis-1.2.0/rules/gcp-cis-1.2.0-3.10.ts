export default {
  id: 'gcp-cis-1.2.0-3.10',
  description:
    // eslint-disable-next-line max-len
    'GCP CIS 3.10 Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpFirewall{
      id
      name
      __typename
      sourceRanges
      direction
      allowed{
        ipProtocol
        ports
      }
    }
  }`,
  resource: 'querygcpFirewall[*]',
  severity: 'unknown',
  conditions: {
    path: '@',
    and: [
      {
        path: '[*].sourceRanges',
        jq: 'map({"range": .})',
        array_all: {
          path: '[*].range',
          in: ['35.191.0.0/16', '130.211.0.0/22'],
        },
      },
      {
        path: '@.allowed',
        jq: `[.[]
          | { "ipProtocol": .ipProtocol}
          + (if .ports | length > 0  then .ports[] else [""][] end  | split("-")  | {fromPort: (.[0]), toPort: (.[1] // .[0])}) ]`,
        array_all: {
          and: [
            {
              path: '[*].ipProtocol',
              in: ['tcp', 'all'],
            },
            {
              path: '[*].fromPort',
              lessThanInclusive: 80,
            },
            {
              path: '[*].toPort',
              greaterThanInclusive: 80,
            },
          ],
        },
      },
    ],
  },
}
