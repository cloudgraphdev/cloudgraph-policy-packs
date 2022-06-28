// AWS NIST 800-53-rev4 Rule equivalent 3.4
export default {
  id: 'aws-cis-1.3.0-2.2.1',  
  title: 'AWS CIS 2.2.1 Ensure EBS volume encryption is enabled',
  
  description: 'Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.',
  
  audit: `**From Console:**
  
  1. Login to AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/
  2. Under Account attributes, click EBS encryption.
  3. Verify Always encrypt new EBS volumes displays Enabled.
  4. Review every region in-use.
  
  **Note:** EBS volume encryption is configured per region.
  
  **From Command Line:**
  
  1. Run
  
          aws --region <region> ec2 get-ebs-encryption-by-default.
  
  2. Verify that "EbsEncryptionByDefault": true is displayed.
  3. Review every region in-use.
  
  **Note:** EBS volume encryption is configured per region.`,
  
  rationale: 'Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.',
  
  remediation: `**From Console:**
  
  1. Login to AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/
  2. Under Account attributes, click EBS encryption.
  3. Click Manage.
  4. Click the Enable checkbox.
  5. Click Update EBS encryption
  6. Repeat for every region requiring the change.
  
  **Note:** EBS volume encryption is configured per region.
  
  **From Command Line:**
  
  1. Run
  
          aws --region <region> ec2 enable-ebs-encryption-by-default.
  
  2. Verify that "EbsEncryptionByDefault": true is displayed.
  3. Repeat every region requiring the change.
  
  **Note:** EBS volume encryption is configured per region.`,
  
  references: [
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
      'https://aws.amazon.com/blogs/aws/new-opt-in-to-default-encryption-for-new-ebs-volumes/',
  ],
  gql: `{
    queryawsEbs {
      id
      arn
      accountId
      __typename
      encrypted
    }
  }`,
  resource: 'queryawsEbs[*]',
  severity: 'high',
  conditions: {
    path: '@.encrypted',
    equal: true,
  },
}
