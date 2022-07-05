// GCP CIS 1.2.0 Rule equivalent 3.6
export default {
  id: 'gcp-nist-800-53-rev4-6.2',
  title:
    'GCP NIST 6.2 Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH)',
  description: `GCP Firewall Rules are specific to a VPC Network. Each rule either allows or denies
  traffic when its conditions are met. Its conditions allow the user to specify the type of
  traffic, such as ports and protocols, and the source or destination of the traffic, including IP
  addresses, subnets, and instances.

  Firewall rules are defined at the VPC network level and are specific to the network in which
  they are defined. The rules themselves cannot be shared among networks. Firewall rules
  only support IPv4 traffic. When specifying a source for an ingress rule or a destination for
  an egress rule by address, only an IPv4 address or IPv4 block in CIDR notation can be
  used. Generic (0.0.0.0/0) incoming traffic from the internet to VPC or VM instance using
  SSH on Port 22 can be avoided.`,
  audit: `**From the Console:**

  1. Go to *VPC network*.
  2. Go to the *Firewall Rules*.
  3. Ensure that *Port* is not equal to *22* and *Action* is not set to *Allow*.
  4. Ensure *IP Ranges* is not equal to *0.0.0.0/0* under *Source filters*.

  **From Command Line:**

      gcloud compute firewall-rules list --format=table'(name,direction,sourceRanges,allowed)'

  Ensure that there is no rule matching the below criteria:

  - *SOURCE_RANGES* is 0.0.0.0/0
  - AND *DIRECTION* is *INGRESS*
  - AND IPProtocol is *tcp* or ALL
  - AND *PORTS* is set to *22* or *range* *containing* *22* or *Null* *(not set)*

  Note:

  - When ALL TCP ports are allowed in a rule, PORT does not have any value set (*NULL*)
  - When ALL Protocols are allowed in a rule, PORT does not have any value set (*NULL*)`,
  rationale:
    'GCP *Firewall Rules* within a *VPC Network* apply to outgoing (egress) traffic from instances and incoming (ingress) traffic to instances in the network. Egress and ingress traffic flows are controlled even if the traffic stays within the network (for example, instance-to-instance communication). For an instance to have outgoing Internet access, the network must have a valid Internet gateway route or custom route whose destination IP is specified. This route simply defines the path to the Internet, to avoid the most general *(0.0.0.0/0)* destination *IP Range* specified from the Internet through SSH with the default *Port 22*. Generic access from the Internet to a specific IP Range needs to be restricted.',
  remediation: `**From the Console:**

  1. Go to *VPC Network*.
  2. Go to the *Firewall Rules*.
  3. Click the *Firewall Rule* you want to modify.
  4. Click *Edit*.
  5. Modify *Source IP ranges* to specific *IP*.
  6. Click *Save*.

  **From Command Line:**
  1. Update the Firewall rule with the new *SOURCE_RANGE* from the below command:

      gcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[- PORT]],...] --source-ranges=[CIDR_RANGE,...]
  `,
  references: ['https://cloud.google.com/vpc/docs/firewalls#blockedtraffic'],
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
  exclude: { not: { path: '@.direction', equal: 'INGRESS' } },
  resource: 'querygcpFirewall[*]',
  severity: 'high',
  check: ({ resource }: any): boolean => {
    return !(
      resource.direction === 'INGRESS' &&
      resource.sourceRanges.some((ip: string) =>
        ['0.0.0.0/0', '::/0'].includes(ip)
      ) &&
      resource.allowed.some(
        ({ ipProtocol, ports }: { ipProtocol: string; ports: string[] }) => {
          return (
            ['tcp', 'all'].includes(ipProtocol) &&
            (!ports.length ||
              ports.some((port: string) => {
                const range = port.includes('-')
                  ? port.split('-')
                  : [port, port]
                return Number(range[0]) <= 22 && Number(range[1]) >= 22
              }))
          )
        }
      )
    )
  },
}
