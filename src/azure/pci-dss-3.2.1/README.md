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

| Rule                      | Description                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| encryption-check-1        | App Service web apps should have 'HTTPS only' enabled                                                                                |
| encryption-check-2        | MySQL Database server 'enforce SSL connection' should be enabled                                                                     |
| encryption-check-3        | PostgreSQL Database server 'enforce SSL connection' should be enabled                                                                |
| encryption-check-4        | Storage Accounts 'Secure transfer required' should be enabled                                                                        |
| monitoring-check-1        | Monitor audit profile should log all activities                                                                                      |
| monitoring-check-2        | Monitor audit profile should log all activities                                                                                      |
| monitoring-check-3        | Security Center default policy setting ‘Monitor Endpoint Protection’ should be enabled                                               |
| monitoring-check-4        | Monitor log profile should be created                                                                                                |
| monitoring-check-5        | Monitor Activity Log Alert should exist for Create or Update Network Security Group                                                  |
| monitoring-check-6        | Monitor Activity Log Alert should exist for Create or Update Network Security Group Rule                                             |
| monitoring-check-7        | Monitor Activity Log Alert should exist for Create or Update or Delete SQL Server Firewall Rule                                      |
| monitoring-check-8        | Monitor Activity Log Alert should exist for Create or Update Security Solution                                                       |
| monitoring-check-9        | Monitor Activity Log Alert should exist for Create Policy Assignment                                                                 |
| monitoring-check-10       | Monitor Activity Log Alert should exist for Delete Network Security Group                                                            |
| monitoring-check-11       | Monitor Activity Log Alert should exist for Delete Network Security Group Rule                                                       |
| monitoring-check-12       | Monitor Activity Log Alert should exist for Delete Security Solution                                                                 |
| monitoring-check-13       | Monitor log profile should have activity logs for global services and all regions                                                    |
| monitoring-check-14       | SQL Server auditing should be enabled                                                                                                |
| network-access-check-1    | MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                      |
| network-access-check-2    | PostgreSQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                 |
| network-access-check-3    | SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0                                                 |
| network-access-check-4    | Ensure default network access rule for Storage Accounts is set to deny                                                               |
| networking-check-1        | Virtual Network security groups should not permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP)                                    |
| networking-check-2        | Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols |
| networking-check-3        | Virtual Network security groups should not permit ingress from '0.0.0.0/0' to TCP/UDP port 22 (SSH)                                  |
| policy-version-check-1    | App Service web apps should have 'Minimum TLS Version' set to '1.2'                                                                  |
| threat-mitigation-check-1 | Ensure Azure Application Gateway Web application firewall (WAF) is enabled                                                           |
| user-check-1              | Active Directory custom subscription owner roles should not be created                                                               |
