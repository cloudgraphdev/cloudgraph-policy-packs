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
| AWS NIST 3.1  | IAM default audit log config should not exempt any users                                                                           |
| AWS NIST 3.2  | PostgreSQL database instance 'log_checkpoints' database flag should be set to 'on'                                                 |
| AWS NIST 3.3  | PostgreSQL database instance 'log_connections' database flag should be set to 'on'                                                 |
| AWS NIST 3.4  | PostgreSQL database instance 'log_disconnections' database flag should be set to 'on'                                              |
| AWS NIST 3.5  | PostgreSQL database instance 'log_lock_waits' database flag should be set to 'on'                                                  |
| AWS NIST 3.6  | PostgreSQL database instance 'log_min_error_statement' database flag should be set appropriately                                   |
| AWS NIST 3.7  | PostgreSQL database instance 'log_temp_files' database flag should be set to '0' (on)                                              |
| AWS NIST 3.8  | PostgreSQL database instance 'log_min_duration_statement' database flag should be set to '-1' (disabled)                           |
| AWS NIST 3.9  | At least one project-level logging sink should be configured with an empty filter                                                  |
| AWS NIST 4.1  | Compute instance disks should be encrypted with customer-supplied encryption keys (CSEKs)                                          |
| AWS NIST 4.2  | SQL database instances should require incoming connections to use SSL                                                              |
