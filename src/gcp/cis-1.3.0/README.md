# CIS Google Cloud Platform Foundations 1.3.0

Policy Pack based on the GCP Foundations 1.3.0 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack for CIS Google Cloud Platform Foundations benchmark using `cg policy add gcp-cis-1.3.0` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
       CISFindings {
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
       CISFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule           | Description                                                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
