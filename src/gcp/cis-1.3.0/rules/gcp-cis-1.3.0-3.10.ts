export default {
  id: 'gcp-cis-1.3.0-3.10',
  title:
    'Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are \'Allowed\'',
  description: `IAP authenticates the user requests to your apps via a Google single sign in. You can then 
  manage these users with permissions to control access. It is recommended to use both IAP 
  permissions and firewalls to restrict this access to your apps with sensitive information.`,

  audit: `**From Console:**

  1. For each of your apps that have IAP enabled go to the Cloud Console VPC network > Firewall rules.
  2. Verify that the only rules correspond to the following values:
    o *Targets:* All instances in the network
    o *Source IP ranges IAP Proxy Addresses*
      ▪ 35.235.240.0/20 Google Health Check
    o 130.211.0.0/22 Google Health Check
    o 35.191.0.0/16 
    o Protocols and ports:
      ▪ Specified protocols and ports required for access and management of your app. For example most health check connection protocols would be covered by;
      ▪ tcp:80 (Default HTTP Health Check port)
    o tcp:443--(Default HTTPS Health Check port)
      
    Note: if you have custom ports used by your load balancers, you will need to list them here`,
  rationale: `IAP ensure that access to VMs is controlled by authenticating incoming requests. Access to 
  your apps and the VMs should be restricted by firewall rules that allow only the proxy IAP 
  IP addresses contained in the 35.235.240.0/20 subnet. Otherwise, unauthenticated 
  requests can be made to your apps. To ensure that load balancing works correctly health 
  checks should also be allowed.`,
  remediation: `**From Console:**

  1. Go to the Cloud Console VPC network > Firewall rules.
  2. Select the checkbox next to the following rules:
    o default-allow-http
    o default-allow-https
    o default-allow-internal
  3. Click *Delete.*
  4. Click *Create firewall rule* and set the following values:
    o *Name:* allow-iap-traffic
    o *Targets:* All instances in the network
      • Source IP ranges (press Enter after you paste each value in the box, copy the value below the bold text including the dash):
        *IAP Proxy Addresses*
      - 35.235.240.0/20
        *Google Health Check*
    o 130.211.0.0/22 Google Health Check
    o Protocols and ports:
      ▪ Specified protocols and ports required for access and management of your app. For example most health check connection protocols would be covered by;
      ▪ tcp:80 (Default HTTP Health Check port)
    o tcp:443--(Default HTTPS Health Check port)
      *Note: if you have custom ports used by your load balancers, you will need to list them here*
  5. When you're finished updating values, click Create.
  
  *Default Value:*

    By default all traffic is allowed.`,
  references: [
    'https://cloud.google.com/iap/docs/concepts-overview',
    'https://cloud.google.com/iap/docs/concepts-overview',
    'https://cloud.google.com/iap/docs/load-balancer-howto',
    'https://cloud.google.com/load-balancing/docs/health-checks',
    'https://cloud.google.com/blog/products/identity-security/cloud-iap-enables-context-aware-access-to-vms-via-ssh-and-rdp-without-bastion-hosts',
  ],
  severity: 'medium',
}
