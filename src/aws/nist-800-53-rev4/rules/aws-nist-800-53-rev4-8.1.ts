export default {
  id: 'aws-nist-800-53-rev4-8.1',  
  title: 'AWS NIST 8.1 ELB listener security groups should not be set to TCP all',
  
  description: 'ELB security groups should permit access only to necessary ports to prevent access to potentially vulnerable services on other ports.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [EC2](https://console.aws.amazon.com/ec2/).
  - In the left navigation, select Load Balancers.
  - Select the desired load balancer.
  - In the Description tab under Security, take note of the security groups associated with the load balancer.
  - In the left navigation, select Security Groups.
  - Search and select the security groups from the previous step.
  - Click the Inbound tab. Click Edit and remove any references to TCP all.
  - Click Save.
  - Click the Outbound tab. Click Edit and remove any references to TCP all.
  - Click Save.
  
  **AWS CLI**
  
  List all load balancers and their attributes:
  
          aws elb describe-load-balancers
  
  - Make note of each Security Group ID associated with each ELB.
  
  Get security group details:
  
          aws ec2 describe-security-groups --group-ids <group id>
  
  - In the output, if FromPort is 0 and ToPort is 65535, this means the rule Type is ALL TCP. If this is the case, run the following command to remove those rules.
  
  Remove the rule that opens all tcp ports:
  
      aws ec2 revoke-security-group-ingress --protocol tcp --port 0-65535 --cidr <cidr block> --group-id <group id>
  
      aws ec2 revoke-security-group-egress --protocol tcp --port 0-65535 --cidr <cidr block> --group-id <group id>`,
  
  references: [
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-groups.html',
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-egress.html',
  ], 
  gql: `{
    queryawsElb {
      id
      arn
      accountId
      __typename
      securityGroups {
        inboundRules {
          source
          fromPort
          toPort
        }
        outboundRules {
          source
          fromPort
          toPort
        }
      }
    }
  }`,
  resource: 'queryawsElb[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.securityGroups',
      array_any: {
        or: [
          {
            path: '[*].inboundRules',
            array_any: {
              and: [
                {
                  path: '[*].source',
                  mismatch: /^sg-.*$/,
                },
                {
                  path: '[*].fromPort',
                  in: [0, null],
                },
                {
                  path: '[*].toPort',
                  in: [65535, null],
                },
              ],
            },
          },
          {
            path: '[*].outboundRules',
            array_any: {
              and: [
                {
                  path: '[*].source',
                  mismatch: /^sg-.*$/,
                },
                {
                  path: '[*].fromPort',
                  in: [0, null],
                },
                {
                  path: '[*].toPort',
                  in: [65535, null],
                },
              ],
            },
          },
        ],
      },
    },
  },
}
