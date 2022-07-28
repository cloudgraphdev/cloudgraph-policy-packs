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

## Available Ruleset

| Rule            | Description                                                                                                                                         |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Azure NIST 1.1  | Virtual Machines unattached disks should be encrypted                                                                                               |
| Azure NIST 1.2  | Virtual Machines data disks (non-boot volumes) should be encrypted                                                                                  |
| Azure NIST 2.1  | Monitor audit profile should log all activities                                                                                                     |
| Azure NIST 2.2  | Key Vault logging should be enabled                                                                                                                 |
| Azure NIST 2.3  | Monitor log profile should be created                                                                                                               |
| Azure NIST 2.4  | Monitor log profile should have activity logs for global services and all regions                                                                   |
| Azure NIST 2.5  | SQL Server auditing should be enabled                                                                                                               |
| Azure NIST 3.1  | Monitor Activity Log Alert should exist for Create or Update Network Security Group                                                                 |
| Azure NIST 3.2  | Monitor Activity Log Alert should exist for Create or Update Network Security Group Rule                                                            |
| Azure NIST 3.3  | Monitor Activity Log Alert should exist for Create or Update or Delete SQL Server Firewall Rule                                                     |
| Azure NIST 3.4  | Monitor Activity Log Alert should exist for Delete Network Security Group                                                                           |
| Azure NIST 3.5  | Monitor Activity Log Alert should exist for Delete Network Security Group Rule                                                                      |
| Azure NIST 3.6  | Virtual Network Network Watcher should be enabled                                                                                                   |
| Azure NIST 4.1  | Security Center default policy setting ‘Monitor Network Security Groups’ should be enabled                                                          |
| Azure NIST 4.2  | Security Center default policy setting ‘Monitor OS Vulnerabilities’ should be enabled                                                               |
| Azure NIST 4.3  | Security Center default policy setting ‘Monitor Vulnerability Assessment’ should be enabled                                                         |
| Azure NIST 4.4  | App Service web apps should have 'Minimum TLS Version' set to '1.2'                                                                                 |
| Azure NIST 5.1  | MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                                     |
| Azure NIST 5.2  | PostgreSQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                                |
| Azure NIST 5.3  | SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                                                |
| Azure NIST 5.4  | Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols                |
| Azure NIST 5.5  | Virtual Network security groups should not permit ingress from "0.0.0.0/0" to TCP/UDP port 22 (SSH)                                                 |
| Azure NIST 5.6  | Virtual Network security groups should not permit ingress from "0.0.0.0/0" to TCP/UDP port 3389 (RDP)                                               |
| Azure NIST 7.1  | PostgreSQL Database configuration "connection_throttling" should be on                                                                              |
| Azure NIST 8.1  | Active Directory custom subscription owner roles should not be created                                                                              |