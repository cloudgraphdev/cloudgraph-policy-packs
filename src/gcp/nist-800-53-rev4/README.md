# NIST 800-53 Rev. 4 for Google Cloud Services

Policy Pack based on the [800-53 Rev. 4](https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/archive/2015-01-22) benchmark provided by the [The National Institute of Standards and Technology (NIST)](https://www.nist.gov)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack NIST 800-53 Rev. 4 for Google Cloud Services benchmark using `cg policy add gcp-nist-800-53-rev4` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
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
     querygcpNISTFindings {
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
       NISTFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule          | Description                                                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| AWS NIST 1.1  | Compute instances should not use the default service account                                                                       |
| AWS NIST 1.2  | Compute instances should not use the default service account with full access to all Cloud APIs                                    |
| AWS NIST 1.3  | Compute instance "block-project-ssh-keys should be enabled                                                                         |
| AWS NIST 1.4  | Compute instances should not have public IP addresses                                                                              |
| AWS NIST 1.5  | Compute instances "Enable connecting to serial ports" should not be enabled                                                        |
| AWS NIST 1.6  | SQL database instances should not permit access from 0.0.0.0/0                                                                     |
| AWS NIST 1.7  | SQL database instances should not have public IPs                                                                                  |
| AWS NIST 2.1  | DNS managed zone DNSSEC should be enabled                                                                                          |
| AWS NIST 2.2  | DNS managed zone DNSSEC key-signing keys should not use RSASHA1                                                                    |
| AWS NIST 2.3  | DNS managed zone DNSSEC zone-signing keys should not use RSASHA1                                                                   |
