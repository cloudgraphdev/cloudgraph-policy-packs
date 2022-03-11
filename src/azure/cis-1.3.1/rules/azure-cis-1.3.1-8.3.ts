export default {
  id: 'azure-cis-1.3.1-8.3',  
  title: 'Azure CIS 8.3 Ensure that Resource Locks are set for mission critical Azure resources',
  
  description: 'Resource Manager Locks provide a way for administrators to lock down Azure resources to prevent deletion of, or modifications to, a resource. These locks sit outside of the Role Based Access Controls (RBAC) hierarchy and, when applied, will place restrictions on the resource for all users. These locks are very useful when there is an important resource in a subscription that users should not be able to delete or change. Locks can help prevent accidental and malicious changes or deletion.',
  
  audit: `**From Azure Console**
  
  1. Navigate to the specific Azure Resource or Resource Group
  2. Click on Locks
  3. Ensure the lock is defined with name and description, type as CanNotDelete or ReadOnly as appropriate.
  
  **Using Azure Command Line Interface 2.0**  
  Review the list of all locks set currently:
  
      az lock list --resource-group <resourcegroupname> --resource-name <resourcename> --namespace <Namespace> --resource-type <type> --parent ""`,
  
  rationale: `As an administrator, it may be necessary to lock a subscription, resource group, or resource to prevent other users in the organization from accidentally deleting or modifying critical resources. The lock level can be set to to CanNotDelete or ReadOnly to achieve this purpose.
  
  - CanNotDelete means authorized users can still read and modify a resource, but they can't delete the resource.
  - ReadOnly means authorized users can read a resource, but they can't delete or update the resource. Applying this lock is similar to restricting all authorized users to the   permissions granted by the Reader role.`,
  
  remediation: `**From Azure Console**
  
  1. Navigate to the specific Azure Resource or Resource Group
  2. For each of the mission critical resource, click on Locks
  3. Click Add
  4. Give the lock a name and a description, then select the type, CanNotDelete or ReadOnly as appropriate
  
  **Using Azure Command Line Interface 2.0**  
  To lock a resource, provide the name of the resource, its resource type, and its resource group name.
  
      az lock create --name <LockName> --lock-type <CanNotDelete/Read-only> --resource-group <resourceGroupName> --resource-name <resourceName> --resource-type <resourceType>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-lock-resources',
      'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-subscription-governance#azure-resource-locks',
  ],  
  severity: 'high'
}
