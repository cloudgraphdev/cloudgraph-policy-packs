export default {
  id: 'gcp-cis-1.2.0-3.4',
  description:
    'GCP CIS 3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC',
  audit: `Currently there is no support to audit this setting through console.

  **From Command Line:**  
  Ensure the property algorithm for keyType keySigning is not using *RSASHA1*.
  
      gcloud dns managed-zones describe ZONENAME --format="json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)"`,
  rationale: `Domain Name System Security Extensions (DNSSEC) algorithm numbers in this registry may be used in CERT RRs. Zonesigning (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms.

  The algorithm used for key signing should be a recommended one and it should be strong. When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, the user can select the DNSSEC signing algorithms and the denial-of-existence type. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If there is a need to change the settings for a managed zone where it has been enabled, turn DNSSEC off and then re-enable it with different settings.`,
  remediation: `1. If it is necessary to change the settings for a managed zone where it has been enabled, NSSEC must be turned off and re-enabled with different settings. To turn off DNSSEC, run the following command:

  gcloud dns managed-zones update ZONE_NAME --dnssec-state off


2. To update key-signing for a reported managed DNS Zone, run the following command:

  gcloud dns managed-zones update ZONE_NAME --dnssec-state on --ksk-algorithm KSK_ALGORITHM --ksk-key-length KSK_KEY_LENGTH --zsk-algorithm ZSK_ALGORITHM - -zsk-key-length ZSK_KEY_LENGTH --denial-of-existence DENIAL_OF_EXISTENCE`,
  references: [
    `https://cloud.google.com/dns/dnssec-advanced#advanced_signing_options`,
  ],
  gql: `{
    querygcpDnsManagedZone {
      id
      __typename
      visibility
      dnssecConfigDefaultKeySpecs {
        keyType
        algorithm
      }
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
            not: {
              path: '@.dnssecConfigDefaultKeySpecs',
              array_any: {
                and: [
                  {
                    path: '[*].keyType',
                    equal: 'keySigning',
                  },
                  {
                    path: '[*].algorithm',
                    equal: 'rsasha1',
                  },
                ],
              },
            },
          },
        ],
      },
    ],
  },
}
