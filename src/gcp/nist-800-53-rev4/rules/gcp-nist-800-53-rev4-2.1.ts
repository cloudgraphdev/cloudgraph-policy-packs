// GCP CIS 1.2.0 Rule equivalent 3.3
export default {
  id: 'gcp-nist-800-53-rev4-2.1',
  title: 'GCP NIST 2.1 DNS managed zone DNSSEC should be enabled',
  description: `Cloud Domain Name System (DNS) is a fast, reliable and cost-effective domain name system
  that powers millions of domains on the internet. Domain Name System Security Extensions
  (DNSSEC) in Cloud DNS enables domain owners to take easy steps to protect their domains
  against DNS hijacking and man-in-the-middle and other attacks.`,
  audit: `**From Console:**

  1. Go to *Cloud DNS* by visiting https://console.cloud.google.com/net-services/dns/zones.
  2. For each zone of *Type Public*, ensure that *DNSSEC* is set to *On*.

  **From Command Line:**

  1. List all the Managed Zones in a project:

          gcloud dns managed-zones list

  2. For each zone of *VISIBILITY public*, get its metadata:

          gcloud dns managed-zones describe ZONE_NAME

  3. Ensure that *dnssecConfig.state* property is *on*.`,
  rationale: 'Domain Name System Security Extensions (DNSSEC) adds security to the DNS protocol by enabling DNS responses to be validated. Having a trustworthy DNS that translates a domain name like www.example.com into its associated IP address is an increasingly important building block of today’s web-based applications. Attackers can hijack this process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in- the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to nefarious websites.',
  remediation: `**From Console:**

  1. Go to *Cloud DNS* by visiting https://console.cloud.google.com/net-services/dns/zones.
  2. For each zone of *Type Public*, set *DNSSEC* to *On*.

  **From Command Line:**
  Use the below command to enable *DNSSEC* for Cloud DNS Zone Name.

          gcloud dns managed-zones update ZONE_NAME --dnssec-state on`,
  references: [
    'https://cloudplatform.googleblog.com/2017/11/DNSSEC-now-available-in-Cloud-DNS.html',
    'https://cloud.google.com/dns/dnssec-config#enabling',
    'https://cloud.google.com/dns/dnssec',
  ],
  gql: `{
    querygcpDnsManagedZone {
      id
      __typename
      visibility
      dnssecConfigState
    }
  }`,
  resource: 'querygcpDnsManagedZone[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.visibility',
        equal: 'private',
      },
      {
        and: [
          {
            path: '@.visibility',
            equal: 'public',
          },
          {
            path: '@.dnssecConfigState',
            equal: 'on',
          },
        ],
      },
    ],
  },
}
