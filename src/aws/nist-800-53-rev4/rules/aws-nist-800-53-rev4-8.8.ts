export default {
  id: 'aws-nist-800-53-rev4-8.8',
  title: 'AWS NIST 8.8 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ except to ports 80 and 443',
  
  description: 'VPC firewall rules should not permit unrestricted access from the internet, with the exception of port 80 (HTTP) and port 443 (HTTPS). Web applications or APIs generally need to be publicly accessible.',
  
  audit: `Perform the following to determine if the account is configured as prescribed:
  
  1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
  2. In the left pane, click *Security Groups*
  3. For each security group, perform the following:
  4. Select the security group
  5. Click the *Inbound Rule*s tab
  6. Ensure no rule exists that has a *Source* of *0.0.0.0/0* to ports differents to 80 and 443`,
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [VPC](https://console.aws.amazon.com/vpc/home).
  - In the left navigation pane, click Security Groups.
    - Remove any rules that permit ingress from ‘0.0.0.0/0’ except to ports 80 and 443.
    - Click Save.
  
  **AWS CLI**
  
  List all security groups with an ingress rule of 0.0.0.0/0:

    aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0' --query "SecurityGroups[*].{Name:GroupName,ID:GroupId}"
  
  Remove the inbound rule(s) that permits unrestricted ingress from ‘0.0.0.0/0’ except to ports 80 and 443:
  
    aws ec2 revoke-security-group-ingress --region <region> --group-name <group_name> --protocol <protocol> --port <number> --cidr 0.0.0.0/0`,
  
  references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
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
            not: {
              or: [
                {
                  and: [
                    {
                      path: '[*].fromPort',
                      equal: 80,
                    },
                    {
                      path: '[*].toPort',
                      equal: 80,
                    },
                  ],
                },
                {
                  and: [
                    {
                      path: '[*].fromPort',
                      equal: 443,
                    },
                    {
                      path: '[*].toPort',
                      equal: 443,
                    },
                  ],
                },
              ],
            },
          },
        ],
      },
    },
  },
}
