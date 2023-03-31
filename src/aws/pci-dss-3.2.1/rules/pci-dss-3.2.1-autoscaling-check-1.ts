export default {
  id: 'aws-pci-dss-3.2.1-autoscaling-check-1',
  title:
    'Autoscaling Check 1: Auto Scaling groups associated with a load balancer should use health checks',
  description: `This control checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks.

  PCI DSS does not require load balancing or highly available configurations. However, this check aligns with AWS best practices.`,
  rationale: `PCI DSS 2.2: Develop configuration standards for all system components. Assure that these standards address all known security vulnerabilities and are consistent with industry-accepted system hardening standards.
  Replicating systems using load balancing provides high availability and is a means to mitigate the effects of a DDoS event.

  This is one method used to implement system hardening configurations.`,
  remediation: `*To enable Elastic Load Balancing health checks*

  1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.

  2. On the navigation pane, under Auto Scaling, choose Auto Scaling Groups.

  3. To select the group from the list, choose the right box.

  4. From Actions, choose Edit

  5. For Health Check Type, choose ELB.

  6. For Health Check Grace Period, enter 300.

  7. Choose Save.

  For more information on using a load balancer with an Auto Scaling group, see the [Amazon EC2 Auto Scaling User Guide.](https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html)`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html',
  ],
  gql: `{
    queryawsAsg {
      id
      arn
      accountId
      __typename
      loadBalancerNames
      healthCheckType
    }
  }`,
  resource: 'queryawsAsg[*]',
  severity: 'low',
  conditions: {
    not: {
      and: [
        {
          path: '@.healthCheckType',
          equal: 'EC2',
        },
        {
          path: '@.loadBalancerNames',
          isEmpty: false,
        },
      ]
    },
  },
}
