# Policy Packs

A package based on a set of rules or benchmarks used to guarantee compliance across the existing infrastructure of your cloud provider.

## Getting started

### Prerequisite

To start using Policy Packs with your infrastructure you have to install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start) first.

### Execution

Install and execute policy packs is fast and simple. We follow the following convention for all our packages `@cloudgraph/policy-pack-[benchmark]`. We can start using policies just passing the name of the benchmark as it shows in the following example.

```bash
# Adding a policy pack will include it into the CG configuration file.
cg policy add aws-cis-1.2.0
cg policy add gcp-cis-1.2.0
cg policy add azure-cis-1.3.1

# Perform a scan for the providers to evaluate. It will execute all the configured policies.
cg scan aws gcp azure
```

## Available Policy Packs

| Benchmark |
| ---------------------------
| [CIS Amazon Web Services Foundations 1.2.0](https://www.npmjs.com/package/@cloudgraph/policy-pack-aws-cis-1.2.0)         |
| [CIS Amazon Web Services Foundations 1.3.0](https://www.npmjs.com/package/@cloudgraph/policy-pack-aws-cis-1.3.0)         |
| [CIS Amazon Web Services Foundations 1.4.0](https://www.npmjs.com/package/@cloudgraph/policy-pack-aws-cis-1.4.0)         |
| [AWS PCI Data Security Standard version 3.2.1](https://www.npmjs.com/package/@cloudgraph/policy-pack-aws-pci-dss-3.2.1)      |
| [NIST 800-53 Rev. 4 for Amazon Web Services](https://www.npmjs.com/package/@cloudgraph/policy-pack-aws-nist-800-53-rev4) |
| [CIS Google Cloud Platform Foundations 1.2.0](https://www.npmjs.com/package/@cloudgraph/policy-pack-gcp-cis-1.2.0)       |
| [GCP PCI Data Security Standard version 3.2.1](https://www.npmjs.com/package/@cloudgraph/policy-pack-gcp-pci-dss-3.2.1)   |
| [NIST 800-53 Rev. 4 for Google Cloud Services](https://www.npmjs.com/package/@cloudgraph/policy-pack-gcp-nist-800-53-rev4)   |
| [CIS Microsoft Azure Foundations 1.3.1](https://www.npmjs.com/package/@cloudgraph/policy-pack-azure-cis-1.3.1)           |
| [Azure PCI Data Security Standard version 3.2.1](https://www.npmjs.com/package/@cloudgraph/policy-pack-azure-pci-dss-3.2.1)   |
| [NIST 800-53 Rev. 4 for Microsoft Azure Services](https://www.npmjs.com/package/@cloudgraph/policy-pack-azure-nist-800-53-rev4)   |
