export default {
  id: 'aws-nist-800-53-rev4-8.44',  
  title: 'AWS NIST 8.44 VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to TCP port 389 (LDAP)',
  
  description: 'VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to TCP port 389 (LDAP). Removing unfettered connectivity to LDAP reduces the chance of exposing critical data.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:

  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a port range that includes port *389* and has a *Source* of *0.0.0.0/0*`,
  
  rationale: 'Removing unfettered connectivity to remote console services, such as LDAP, reduces a server\'s exposure to risk.',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/).
  - In the left pane, click Security Groups.
  - For each security group, perform the following:
  - Select the security group.
  - Click the Inbound Rules tab.
  - Identify the rules to be removed.
  - Click the x in the Remove column.
  - Click Save.
  
  **AWS CLI**
  
  Remove the inbound rule(s) that permits unrestricted ingress to TCP port 389 from the selected security group:
  
      aws ec2 revoke-security-group-ingress --region <region> --group-name <group_name> --protocol tcp --port 389 --cidr 0.0.0.0/0
  
  Optionally add a more restrictive ingress rule to the selected security group:
  
      aws ec2 authorize-security-group-ingress --region <region> --group-name <group_name> --protocol tcp --port 389 --cidr <cidr_block>`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules',
      'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/working-with-security-groups.html#updating-security-group-rules',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html',
      'https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html',
  ],
  gql: `{
    queryawsSecurityGroup{
      id
      arn
      accountId
       __typename
      inboundRules{
        source
        toPort
        fromPort
      }
    }
  }`,
  resource: 'queryawsSecurityGroup[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.inboundRules',
      array_any: {
        and: [
          {
            path: '[*].source',
            in: ['0.0.0.0/0', '::/0'],
          },
          {
            or: [
              {
                and: [
                  {
                    path: '[*].fromPort',
                    equal: null,
                  },
                  {
                    path: '[*].toPort',
                    equal: null,
                  },
                ],
              },
              {
                and: [
                  {
                    path: '[*].fromPort',
                    lessThanInclusive: 389,
                  },
                  {
                    path: '[*].toPort',
                    greaterThanInclusive: 389,
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
}
