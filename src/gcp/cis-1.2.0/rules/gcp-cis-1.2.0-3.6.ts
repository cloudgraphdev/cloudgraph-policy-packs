export default {
  id: 'gcp-cis-1.2.0-3.6',
  description:
    'GCP CIS 3.6 Ensure that SSH access is restricted from the internet',
  gql: `{
    querygcpFirewall(filter: {direction:{eq: "INGRESS"}}){
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
  severity: 'warning',
  conditions: {
    not: {
      path: '@',
      and: [
        {
          path: '[*].sourceRanges',
          jq: 'map({"range": .})',
          array_any: {
            path: '[*].range',
            in: ['0.0.0.0/0', '::/0'],
          },
        },
        {
          path: '[*].direction',
          in: ['INGRESS'],
        },
        {
          path: '@.allowed',
          jq: `[.[]
          | { "ipProtocol": .ipProtocol}
          + (if .ports | length > 0  then .ports[] else [""][] end  | split("-")  | {fromPort: (.[0]), toPort: (.[1] // .[0])}) ]`,
          array_any: {
            and: [
              {
                path: '[*].ipProtocol',
                in: ['tcp', 'all'],
              },
              {
                or: [
                  {
                    and: [
                      {
                        path: '[*].fromPort',
                        equal: null,
                      },
                      {
                        path: '[*].toPort',
                        equal: null,
                      },
                    ],
                  },
                  {
                    and: [
                      {
                        path: '[*].fromPort',
                        lessThanInclusive: 22,
                      },
                      {
                        path: '[*].toPort',
                        greaterThanInclusive: 22,
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
  },
}
