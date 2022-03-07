export default {
  id: 'aws-pci-dss-3.2.1-sagemaker-check-1',
  title:
    'SageMaker Check 1: Amazon SageMaker notebook instances should not have direct internet access',
  description: `This control checks whether direct internet access is disabled for an SageMaker notebook instance. To do this, it checks whether the DirectInternetAccess field is disabled for the notebook instance.

  If you configure your SageMaker instance without a VPC, then by default direct internet access is enabled on your instance. You should configure your instance with a VPC and change the default setting to Disable — Access the internet through a VPC.
  
  To train or host models from a notebook, you need internet access. To enable internet access, make sure that your VPC has a NAT gateway and your security group allows outbound connections. To learn more about how to connect a notebook instance to resources in a VPC, see Connect a notebook instance to resources in a VPC in the Amazon SageMaker Developer Guide.
  
  You should also ensure that access to your SageMaker configuration is limited to only authorized users. Restrict users' IAM permissions to modify SageMaker settings and resources.`,
  rationale: `**PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**
  If you use SageMaker notebook instances within your CDE, ensure that the notebook instance does not allow direct internet access. Allowing direct public access to your notebook instance might violate the requirement to allow only necessary traffic to and from the CDE.
  
  **PCI DSS 1.3.1: Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**
  If you use SageMaker notebook instances within your CDE, ensure that the notebook instance does not allow direct internet access. Allowing direct public access to your notebook instance might violate the requirement to only allow access to system components that provide authorized publicly accessible services, protocols, and ports.
  
  **PCI DSS 1.3.2: Limit inbound internet traffic to IP addresses within the DMZ.**
  If you use SageMaker notebook instances within your CDE, ensure that the notebook instance does not allow direct internet access. Allowing direct public access to your notebook instance might violate the requirement to limit inbound traffic to IP addresses within the DMZ.
  
  **PCI DSS 1.3.4: Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.
  If you use SageMaker notebook instances within your CDE, ensure that the notebook instance does not allow direct internet access. Allowing direct public access to your notebook instance might violate the requirement to block unauthorized outbound traffic from the cardholder data environment to the internet
  
  **PCI DSS 1.3.6: Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the DMZ and other untrusted networks.**
  If you use SageMaker notebook instances, and the notebook instance contains cardholder data, restrict direct internet access. Allowing direct public access to your notebook instance might violate the requirement to place system components that store cardholder data in an internal network zone, segregated from the DMZ and other untrusted networks.
  `,
  remediation: `**Note**: that you cannot change the internet access setting after a notebook instance is created. It must be stopped, deleted, and recreated.

  To configure an SageMaker notebook instance to deny direct internet access
  
  1. Open the SageMaker console at https://console.aws.amazon.com/sagemaker/
  
  2. Navigate to Notebook instances.
  
  3. Delete the instance that has direct internet access enabled. Choose the instance, choose Actions, then choose stop.
  
  4. After the instance is stopped, choose Actions, then choose delete.
  
  5. Choose Create notebook instance. Provide the configuration details.
  
  6. Expand the Network section. Then choose a VPC, subnet, and security group. Under Direct internet access, choose Disable — Access the internet through a VPC.
  
  7. Choose Create notebook instance.`,
  references: [
    'https://d1.awsstatic.com/whitepapers/compliance/pci-dss-compliance-on-aws.pdf'
  ],
  gql: `{
    queryawsSageMakerNotebookInstance {
      id
      arn
      accountId
       __typename
       directInternetAccess
    }
  }`,
  resource: 'queryawsSageMakerNotebookInstance[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.directInternetAccess',
      equal: true
    },
  },
}
