export default {
  id: 'gcp-cis-1.2.0-3.5',
  title:
    'GCP CIS 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC',
  description: `DNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing
  (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular
  subsets of these algorithms. The algorithm used for key signing should be a recommended
  one and it should be strong.`,
  audit: `Currently there is no support to audit this setting through the console.

  **From Command Line:**
  Ensure the property algorithm for keyType zone signing is not using RSASHA1.

      gcloud dns managed-zones describe --format="json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)"`,
  rationale: `DNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms.

  The algorithm used for key signing should be a recommended one and it should be strong. When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, the DNSSEC signing algorithms and the denial-of-existence type can be selected. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If the need exists to change the settings for a managed zone where it has been enabled, turn DNSSEC off and then re-enable it with different settings.`,
  remediation: `1. If the need exists to change the settings for a managed zone where it has been
  enabled, DNSSEC must be turned off and then re-enabled with different settings. To
  turn off DNSSEC, run following command:

      gcloud dns managed-zones update ZONE_NAME --dnssec-state off


2. To update zone-signing for a reported managed DNS Zone, run the following
  command:

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
                    equal: 'zoneSigning',
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
