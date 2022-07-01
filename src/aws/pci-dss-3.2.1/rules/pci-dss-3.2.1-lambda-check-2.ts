export default {
  id: 'aws-pci-dss-3.2.1-lambda-check-2',
  title: 'Lambda Check 2: Lambda functions should be in a VPC',
  description: `This control checks whether a Lambda function is in a VPC. You might see failed findings for Lambda@Edge resources.

  It does not evaluate the VPC subnet routing configuration to determine public reachability.

  **Note**
  This control is not supported in the following Regions.

  * Asia Pacific (Osaka)
  * China (Beijing)
  * China (Ningxia)`,
  rationale: `**PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**
  By default, Lambda runs your functions in a secure default VPC with access to AWS services and the internet.

If you use a Lambda function that is in scope for PCI DSS, the function can be configured to use a VPC endpoint. This would allow you to connect to your Lambda function from within a VPC without internet access. This method is used to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.1: Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**
  By default, Lambda runs your functions in a secure default VPC with access to AWS services and the internet.

If you use a Lambda function that is in scope for PCI DSS, the function can be configured to use a VPC endpoint. This allows you to connect to your Lambda function from within a VPC without internet access. This is a method used to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

  **PCI DSS 1.3.2: Limit inbound internet traffic to IP addresses within the DMZ.**
  By default, Lambda runs your functions in a secure default VPC with access to AWS services and the internet.

If you use a Lambda function that is in scope for PCI DSS, the function can be configured to use a VPC endpoint. This allows you to connect to your Lambda function from within a VPC without internet access. This is a method used to limit inbound internet traffic to IP addresses within the DMZ.

  **PCI DSS 1.3.4: Do not allow unauthorized outbound traffic from the cardholder data environment to the internet.**
  By default, Lambda runs your functions in a secure default VPC with access to AWS services and the internet.

If you use a Lambda function that is in scope for PCI DSS, the function can be configured to use a VPC endpoint. This allows you to connect to your Lambda function from within a VPC without internet access. This is a method used to block unauthorized outbound traffic from the cardholder data environment to the internet.
  `,
  remediation: `**To configure a function to connect to private subnets in a virtual private cloud (VPC) in your account**

  1. Open the AWS Lambda console at https://console.aws.amazon.com/lambda/.

  2. Navigate to **Functions** and then select your Lambda function.

  3. Scroll to **Network** and then select a VPC with the connectivity requirements of the function.

  4. To run your functions in high availability mode, Security Hub recommends that you choose at least two subnets.

  5. Choose at least one security group that has the connectivity requirements of the function.

  6. Choose **Save**.
  For more information see the section on configuring a Lambda function to access resources in a VPC in the [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-lambda-2',
  ],
  gql: `{
    queryawsLambda {
      id
      arn
      accountId
       __typename
       vpcConfig {
         vpcId
       }
    }
  }`,
  resource: 'queryawsLambda[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.vpcConfig',
        notEqual: null,
      },
      {
        path: '@.vpcConfig',
        isEmpty: false,
      },
      {
        path: '@.vpcConfig.vpcId',
        isEmpty: false,
      },
    ],
  },
}
