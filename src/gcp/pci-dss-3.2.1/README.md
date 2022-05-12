# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack for GCP PCI DSS benchmark using `cg policy add gcp-pci-dss-3.2.1` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
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
     querygcpCISFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     querygcpIamPolicy {
       id
       PCIFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

<!--
TODO: Uncomment table when rules available
## Available Ruleset
| Rule         | Description                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| -  | -                                    |
-->
