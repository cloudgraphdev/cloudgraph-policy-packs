export default {
  id: 'gcp-cis-1.2.0-2.12',
  description:
    'GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks',
  audit: `**From Command Line:**

  1. List all VPCs networks in a project:
  
          gcloud compute networks list --format="table[box,title='All VPC Networks'](name:label='VPC Network Name')"
  
  2. List all DNS policies, logging enablement, and associated VPC networks:
  
          gcloud dns policies list --flatten="networks[]" -- format="table[box,title='All DNS Policies By VPC Network'](name:label='Policy Name',enableLogging:label='Logging Enabled':align=center,networks.networkUrl.basename():label='VPC Network Name')"
  
  Each VPC Network should be associated with a DNS policy with logging enabled.`,
  rationale: `Security monitoring and forensics cannot depend solely on IP addresses from VPC flow logs, especially when considering the dynamic IP usage of cloud resources, HTTP virtual host routing, and other technology that can obscure the DNS name used by a client from the IP address. Monitoring of Cloud DNS logs provides visibility to DNS names requested by the clients within the VPC. These logs can be monitored for anomalous domain names, evaluated against threat intelligence.

  Note: For full capture of DNS, firewall must block egress UDP/53 (DNS) and TCP/443 (DNS over HTTPS) to prevent client from using external DNS name server for resolution.`,
  remediation: `**From Command Line:  
  Add New DNS Policy With Logging Enabled**
  
  For each VPC network that needs a DNS policy with logging enabled:
  
      gcloud dns policies create enable-dns-logging --enable-logging --description="Enable DNS Logging" --networks=VPC_NETWORK_NAME
  
  The VPC_NETWORK_NAME can be one or more networks in comma-separated list  
  
  **Enable Logging for Existing DNS Policy**  
  For each VPC network that has an existing DNS policy that needs logging enabled:
  
      gcloud dns policies update POLICY_NAME --enable-logging --networks=VPC_NETWORK_NAME
  
  The VPC_NETWORK_NAME can be one or more networks in comma-separated list`,
  references: [`https://cloud.google.com/dns/docs/monitoring`],
  gql: `{
    querygcpNetwork {
      id
      __typename
      dnsPolicy {
        enableLogging
      }
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    not: {
      or: [
        {
          path: '@.dnsPolicy',
          isEmpty: true,
        },
        {
          path: '@.dnsPolicy',
          array_any: {
            path: '[*].enableLogging',
            equal: false,
          },
        },
      ],
    },
  },
}
