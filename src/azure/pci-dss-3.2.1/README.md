# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [Azure Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-azure) for CG with the `cg init azure` command.
3. Add Policy Pack for Microsoft Azure PCI DSS benchmark using `cg policy add azure-pci-dss-3.2.1` command.
4. Execute the ruleset using the scan command `cg scan azure`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryazureFindings {
       PCIFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

   5b. Querying findings by specific benchmark:

   ```graphql
   query {
     queryazurePCIFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     queryazureSecurityPricing {
       id
       PCIFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule               | Description                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| monitoring-check-1 | Monitor audit profile should log all activities                                                                                      |
| monitoring-check-2 | Monitor audit profile should log all activities                                                                                      |
| monitoring-check-3 | Security Center default policy setting ‘Monitor Endpoint Protection’ should be enabled                                               |
| networking-check-1 | Virtual Network security groups should not permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP)                                    |
| networking-check-2 | Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols |
