export default {
  id: 'aws-pci-dss-3.2.1-elasticSearch-check-2',
  title: 'ElasticSearch Check 2: Elasticsearch domains should have encryption at rest enabled',
  description: `This control checks whether Elasticsearch domains have encryption at rest configuration enabled.

  This control is not supported in Asia Pacific (Osaka).`,
  rationale: `**PCI DSS 3.4: Render Primary Account Numbers (PAN) unreadable anywhere it is stored (including on portable digital media, backup media, and in logs).**

  If you use OpenSearch Service to store credit card Primary Account Numbers (PAN), the PAN should be protected by enabling OpenSearch Service domain encryption at rest.

  If enabled, it encrypts the following aspects of a domain: Indices, automated snapshots, OpenSearch Service logs, swap files, all other data in the application directory.

  This is a method used to render PAN unreadable.`,
  remediation: `By default, domains do not encrypt data at rest, and you cannot configure existing domains to use the feature.

  To enable the feature, you must create another domain and migrate your data. For information about creating domains, see the [Amazon OpenSearch Service Developer Guide](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html).
  
  Encryption of data at rest requires OpenSearch Service 5.1 or later. For more information about encrypting data at rest for OpenSearch Service, see the [Amazon OpenSearch Service Developer Guide](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-es-2',
    'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html'
  ],
  gql: `{
    queryawsElasticSearchDomain {
      id
      arn
      accountId
      __typename
      encryptionAtRestOptions {
        enabled
      }
    }
  }`,
  resource: 'queryawsElasticSearchDomain[*]',
  severity: 'medium',
  conditions: {
    path: '@.encryptionAtRestOptions.enabled',
    equal: true
  },
}
