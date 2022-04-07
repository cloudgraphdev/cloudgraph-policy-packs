export default {
  id: 'gcp-cis-1.2.0-3.7',
  title: 'GCP CIS 3.7 Ensure that RDP access is restricted from the internet',
  description: `GCP Firewall Rules are specific to a VPC Network. Each rule either allows or denies
  traffic when its conditions are met. Its conditions allow users to specify the type of traffic,
  such as ports and protocols, and the source or destination of the traffic, including IP
  addresses, subnets, and instances.

  Firewall rules are defined at the VPC network level and are specific to the network in which
  they are defined. The rules themselves cannot be shared among networks. Firewall rules
  only support IPv4 traffic. When specifying a source for an ingress rule or a destination for
  an egress rule by address, an IPv4 address or IPv4 block in CIDR notation can be used.
  Generic (0.0.0.0/0) incoming traffic from the Internet to a VPC or VM instance using RDP
  on Port 3389 can be avoided.`,
  audit: `**From the Console:**

  1. Go to *VPC network*.
  2. Go to the *Firewall Rules*.
  3. Ensure *Port* is not equal to *3389* and *Action* is not *Allow*.
  4. Ensure *IP Ranges* is not equal to *0.0.0.0/0* under *Source filters*.

  **From Command Line:**

      gcloud compute firewall-rules list -- format=table'(name,direction,sourceRanges,allowed.ports)'

  Ensure that there is no rule matching the below criteria:

  - *SOURCE_RANGES* is *0.0.0.0/0*
  - AND *DIRECTION* is *INGRESS*
  - AND IPProtocol is *TCP* or *ALL*
  - AND *PORTS* is set to *3389* or *range containing 3389* or *Null (not set)*

  Note:

  - When ALL TCP ports are allowed in a rule, PORT does not have any value set (*NULL*)
  - When ALL Protocols are allowed in a rule, PORT does not have any value set (*NULL*)`,
  rationale: `GCP *Firewall Rule*s within a *VPC Network*. These rules apply to outgoing (egress) traffic from instances and incoming (ingress) traffic to instances in the network. Egress and ingress traffic flows are controlled even if the traffic stays within the network (for example, instance-to-instance communication). For an instance to have outgoing Internet access, the network must have a valid Internet gateway route or custom route whose destination IP is specified. This route simply defines the path to the Internet, to avoid the most general (0.0.0.0/0) destination IP Range specified from the Internet through RDP with the default *Port 3389*. Generic access from the Internet to a specific IP Range should be restricted.`,
  remediation: `**From the Console:**

  1. Go to *VPC Network*.
  2. Go to the *Firewall Rules*.
  3. Click the *Firewall Rule* to be modified.
  4. Click *Edit*.
  5. Modify *Source IP ranges* to specific *IP*.
  6. Click *Save*.

  **From Command Line:**
  1. Update RDP Firewall rule with new *SOURCE_RANGE* from the below command:

          gcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[-PORT]],...] --source-ranges=[CIDR_RANGE,...]`,
  references: [`https://cloud.google.com/vpc/docs/firewalls#blockedtraffic`],
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
  severity: 'high',
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
                        lessThanInclusive: 3986,
                      },
                      {
                        path: '[*].toPort',
                        greaterThanInclusive: 3986,
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
