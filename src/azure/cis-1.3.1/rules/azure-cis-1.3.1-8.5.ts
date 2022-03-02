export default {
  id: 'azure-cis-1.3.1-8.5',  
  title: 'Azure CIS 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services',
  
  description: 'Ensure that RBAC is enabled on all Azure Kubernetes Services Instances',
  
  audit: `**From Azure Console**
  
  1. Go to Kubernetes Services
  2. For each Kubernetes Services instance, click on Automation Script.
  3. Ensure that each variable "enableRBAC" is set to true.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure that the output of the below command is not empty or null.
  
      az aks show --name <AKS Instance Name> --query enableRbac --resource-group <Resource Group Name> --subscription <Subscription ID>`,
  
  rationale: 'Azure Kubernetes Services has the capability to integrate Azure Active Directory users and groups into Kubernetes RBAC controls within the AKS Kubernetes API Server. This should be utilized to enable granular access to Kubernetes resources within the AKS clusters supporting RBAC controls not just of the overarching AKS instance but also the individual resources managed within Kubernetes.',
  
  remediation: 'WARNING: This setting cannot be changed after AKS deployment, cluster will require recreation.',
  
  references: [
      'https://docs.microsoft.com/en-us/azure/aks/aad-integrationhttps://kubernetes.io/docs/reference/access-authn-authz/rbac/https://docs.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-list',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle',
  ],  
  gql: `{
    queryazureAksManagedCluster {
      id
      __typename
      enableRbac
    }
  }`,
  resource: 'queryazureAksManagedCluster[*]',
  severity: 'low',
  conditions: {
    path: '@.enableRbac',
    equal: true,
  },
}
