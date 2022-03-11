export default {
  id: 'aws-pci-dss-3.2.1-redshift-check-1',
  title:
    'Redshift Check 1: Amazon Redshift clusters should prohibit public access',
  description: `This control checks whether Amazon Redshift clusters are publicly accessible by evaluating the publiclyAccessible field in the cluster configuration item.
  
  **Note**
  This control is not supported in Asia Pacific (Osaka).`,
  rationale: `**PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**
  
  If you use an Amazon Redshift cluster to store cardholder data, the cluster should not be publicly accessible. Allowing this might violate the requirement to allow only necessary traffic to and from the CDE.
  
  **PCI DSS 1.3.1: Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**
  
  If you use an Amazon Redshift cluster to store cardholder data, the cluster should not be publicly accessible. Allowing this might violate the requirement to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.
  
  **PCI DSS 1.3.2: Limit inbound internet traffic to IP addresses within the DMZ.**
 
  If you use an Amazon Redshift cluster to store cardholder data, the cluster should not be publicly accessible, as this may violate the requirement to limit inbound internet traffic to IP addresses within the DMZ.
  
  **PCI DSS 1.3.4: Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.
 
  If you use an Amazon Redshift cluster to store cardholder data, the cluster should not be publicly accessible. Allowing this may violate the requirement to block unauthorized outbound traffic from the cardholder data environment to the internet.
  
  **PCI DSS 1.3.6: Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the DMZ and other untrusted networks.**
 
  If you use an Amazon Redshift cluster to store cardholder data, the cluster should not be publicly accessible. Allowing this might violate the requirement to place system components that store cardholder data in an internal network zone, segregated from the DMZ and other untrusted networks.
  `,
  remediation: `
  **To disable public access for an Amazon Redshift cluster**
  
  1. Open the Amazon Redshift console at https://console.aws.amazon.com/redshift/.
  
  2. On the navigation pane, choose **Clusters** and then select your public Amazon Redshift cluster.
  
  3. From the **Cluster** drop-down menu, choose **Modify cluster**.
  
  4. In **Publicly accessible**, choose **No**.
  
  5. Choose **Modify**.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-redshift-1',
    'https://d1.awsstatic.com/whitepapers/compliance/pci-dss-compliance-on-aws.pdf'
  ],
  gql: `{
    queryawsRedshiftCluster {
      id
      arn
      accountId
      __typename
      publiclyAccessible
    }
  }`,
  resource: 'queryawsRedshiftCluster[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.publiclyAccessible',
      equal: true
    },
  },
}
