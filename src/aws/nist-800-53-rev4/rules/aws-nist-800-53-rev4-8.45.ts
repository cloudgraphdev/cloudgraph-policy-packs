export default {
  id: 'aws-nist-800-53-rev4-8.45',
  title: 'AWS NIST 8.45 VPC security groups attached to RDS instances should not permit ingress from ‘0.0.0.0/0’ to all ports',
  
  description: 'RDS security groups should permit access only to necessary ports to prevent access to potentially vulnerable services on other ports.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a port range that includes port *0-65535* and has a *Source* of *0.0.0.0/0*`,
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/).
  - In the left navigation, select Security Groups.
  - Select the desired security group and click the Inbound tab.
  - Click Edit rules.
  - Remove any permissions that allow ‘0.0.0.0/0’ to all ports.
  
  **AWS CLI**
  
  Remove ingress rules which allow connectivity from anywhere to all ports and protocols:
  
      aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions <ip_permissions>`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules',
      'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/working-with-security-groups.html#updating-security-group-rules',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html',
  ],
  gql: `{
    queryawsRdsDbInstance {
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
      }
    }
  }`,
  resource: 'queryawsRdsDbInstance[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.securityGroups',
      array_any: {
        path: '[*].inboundRules',
        array_any: {
          and: [
            {
              path: '[*].source',
              in: ['0.0.0.0/0', '::/0'],
            },
            {
              and: [
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
          ],
        },
      },
    },
  },
}
