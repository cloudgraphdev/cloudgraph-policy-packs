export default {
  id: 'gcp-cis-1.2.0-3.10',
  title:
    'GCP CIS 3.10 Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses',
  description: `Access to VMs should be restricted by firewall rules that allow only IAP traffic by ensuring
  only connections proxied by the IAP are allowed. To ensure that load balancing works
  correctly health checks should also be allowed.`,
  audit: `From the Console:

  1. Go to the Cloud Console VPC network > Firewall rules.
  2. Verify that the only rules correspond to the following values:

      - **Targets** : All instances in the network
      - **Source IP ranges** (press Enter after you paste each value in the box):
          - 130.211.0.0/22
          - 35.191.0.0/16
      - **Protocols and ports** :
          - Specified protocols and ports
          - tcp:80`,
  rationale: `IAP ensure that access to VMs is controlled by authenticating incoming requests. However if the VM is still accessible from IP addresses other than the IAP it may still be possible to send unauthenticated requests to the instance. Care must be taken to ensure that loadblancer health checks are not blocked as this would stop the loadbalancer from correctly knowing the health of the VM and loadbalancing correctly.`,
  remediation: `From the Console:

  1. Go to the Cloud Console [VPC network > Firewall rules](https://console.cloud.google.com/networking/firewalls/list?_ga=2.72166934.480049361.1580860862-1336643914.1580248695).
  2. Select the checkbox next to the following rules:
      - default-allow-http
      - default-allow-https
      - default-allow-internal
  3. Click **Delete**.
  4. Click **Create firewall rule** and set the following values:
      -  **Name** : allow-iap-traffic
      - **Targets** : All instances in the network
      - **Source IP ranges** (press Enter after you paste each value in the box):
          - 130.211.0.0/22
          - 35.191.0.0/16
      - **Protocols and ports**:
          - Specified protocols and ports
          - tcp:80
  5. When you're finished updating values, click **Create**.`,
  references: [],
  gql: `{
    querygcpFirewall{
      id
      name
      __typename
      sourceRanges
      direction
      allowed{
        ipProtocol
        ports
      }
    }
  }`,
  resource: 'querygcpFirewall[*]',
  severity: 'unknown',
  check: ({ resource }: any): boolean => {
    return (
      resource.sourceRanges.every((ip: string) =>
        ['35.191.0.0/16', '130.211.0.0/22'].includes(ip)
      ) &&
      resource.allowed.every(
        ({ ipProtocol, ports }: { ipProtocol: string; ports: string[] }) => {
          return (
            ['tcp', 'all'].includes(ipProtocol) &&
            ports.length &&
            ports.every((port: string) => {
              const range = port.includes('-') ? port.split('-') : [port, port]
              return Number(range[0]) === 80 && Number(range[1]) === 80
            })
          )
        }
      )
    )
  },
}
