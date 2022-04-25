export default {
  id: 'aws-nist-800-53-rev4-12.2',  
  title: 'EC2 instances should not have a public IP association (IPv4)',
  
  description: `EC2 instances are reachable over the internet even if you have protections such as 
  NACLs or security groups if a public IP address is associated with an instance. To minimize the risk 
  of unauthorized access to your instances, do not allow public IP associations unless absolutely necessary.`,

  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**

  Modify the public IPv4 addressing attribute
  - Navigate to the VPC console.
  - In the navigation pane, choose Subnets.
  - Select your subnet and choose Subnet Actions, Modify auto-assign IP settings.
  - The Enable auto-assign public IPv4 address check box, if selected, requests a public IPv4 address for all instances launched into the selected subnet. Select or clear the check box as required, and then choose Save.

Disable the public IP addressing feature

  - Navigate to EC2.
  - Choose Launch Instance.
  - Select an AMI and an instance type, and then choose Next: Configure Instance Details.
  - On the Configure Instance Details page, for Network, select a VPC. The Auto-assign Public IP list is displayed. Choose Disable to override the default setting for the subnet.

  **AWS CLI**

  - Use the 
  > run-instances 
  - command with the 
  > --no-associate-public-ip-address, or
  - Execute the 
  > modify-subnet-attribute 
  - command with 
  > --no-map-customer-owned-ip-on-launch`,

  references: [
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
      'https://aws.amazon.com/blogs/containers/how-amazon-ecs-manages-cpu-and-memory-resources/',
  ],
  gql: `{
    queryawsEc2 {
      id
      arn
      accountId
      __typename      
      subnet {        
        autoAssignPublicIpv4Address
      }
    }    
  }`,
  resource: 'queryawsEc2[*]',
  severity: 'medium',
  conditions: {
    path: '@.subnet',
    array_all: {
      path: '[*].autoAssignPublicIpv4Address',
      notEqual: 'Yes'
    },
  },
}