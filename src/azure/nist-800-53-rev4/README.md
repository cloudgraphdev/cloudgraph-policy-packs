# NIST 800-53 Rev. 4 for Microsoft Azure Services

Policy Pack based on the [800-53 Rev. 4](https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/archive/2015-01-22) benchmark provided by the [The National Institute of Standards and Technology (NIST)](https://www.nist.gov)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [Azure Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-azure) for CG with the `cg init azure` command.
3. Add Policy Pack NIST 800-53 Rev. 4 for Microsoft Azure Services benchmark using `cg policy add azure-nist-800-53-rev4` command.
4. Execute the ruleset using the scan command `cg scan azure`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryazureFindings {
       NISTFindings {
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
     queryazureNISTFindings {
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
       NISTFindings {
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
