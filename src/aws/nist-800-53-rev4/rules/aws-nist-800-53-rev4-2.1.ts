export default {
  id: 'aws-nist-800-53-rev4-2.1',  
  title: 'AWS NIST 2.1 Auto Scaling groups should span two or more availability zones',
  
  description: 'Auto Scaling groups that span two or more availability zones promote redundancy of data, which helps ensure availability and continuity during an adverse situation.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [EC2](https://console.aws.amazon.com/ec2/v2/home).
  - In the left navigation, select Auto Scaling groups.
  - Choose an existing group from the list.
  - In Subnet(s), choose the subnet corresponding to the Availability Zone.
  - Click Save.
  - In the left navigation, select Load Balancers.
  - Choose your load balancer.
  - On the Description tab for Availability Zones, click Edit and add the subnets for the Availability Zone.
  - Click Save
  
  **AWS CLI**
  
  Add a subnet to the Auto Scaling group.
  
      aws autoscaling update-auto-scaling-group --auto-scaling-group-name my-asg --vpc-zone-identifier subnet-41767929 subnet-cb663da2 --min-size 2
  
  Verify that the instances in the new subnet are ready to accept traffic from the load balancer.
  
      aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name my-asg
  
  Enable the new subnet for your Application Load Balancer.
  
      aws elbv2 set-subnets --load-balancer-arn my-lb-arn --subnets subnet-41767929 subnet-cb663da2`,
  
  references: [
      'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html#as-add-az-console',
      'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html#as-add-az-aws-cli',
  ],
  gql: `{
    queryawsAsg {
      id
      arn
      accountId
      __typename
      availabilityZones
    }
  }`,
  resource: 'queryawsAsg[*]',
  severity: 'medium',
  conditions: {
    jq: '[.availabilityZones[]] | { "twoOrMore" : (length >= 2) }',
    path: '@',
    and: [
      {
        path: '@.twoOrMore',
        equal: true,
      },
    ],
  }
}
