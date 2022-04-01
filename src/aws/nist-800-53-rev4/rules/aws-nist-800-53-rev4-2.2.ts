export default {
  id: 'aws-nist-800-53-rev4-2.2',  
  title: 'AWS NIST 2.2 ELBv1 load balancer cross zone load balancing should be enabled',
  
  description: 'Having Availability Zone with the Cross-Zone Load Balancing feature enabled for the VPC reduces the risk of failure at a single location as the AWS Elastic Load Balancers distribute the traffic to the other locations.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [EC2](https://console.aws.amazon.com/ec2/home).
  - On the navigation pane, under LOAD BALANCING, choose Load Balancers.
  - Select the load balancer associated with your VPC.
  - On the Description tab, choose Change cross-zone load balancing setting.
  - On the Configure Cross-Zone Load Balancing page, select Enable.
  - Choose Save.
  
  **AWS CLI**
  
      aws elb modify-load-balancer-attributes --load-balancer-name <name> --load-balancer-attributes "{"CrossZoneLoadBalancing":{"Enabled":true}}"`,
  
  references: [
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html#enable-cross-zone',
      'https://docs.aws.amazon.com/cli/latest/reference/elb/modify-load-balancer-attributes.html',
      'https://docs.aws.amazon.com/cli/latest/reference/elb/modify-load-balancer-attributes.html',
  ],
  gql: `{
    queryawsElb {
      id
      arn
      accountId
      __typename
      crossZoneLoadBalancing
    }
  }`,
  resource: 'queryawsElb[*]',
  severity: 'medium',
  conditions: {
    path: '@.crossZoneLoadBalancing',
    equal: 'Enabled',
  }
}
