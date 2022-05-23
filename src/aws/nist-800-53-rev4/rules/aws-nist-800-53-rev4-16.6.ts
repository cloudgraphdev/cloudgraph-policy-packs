export default {
  id: 'aws-nist-800-53-rev4-16.6',
  title:
    'AWS NIST 16.6 ELBv2 HTTPS listeners should use secure TLS protocol versions (1.2 and above)',

  description:
    'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible. Versions prior to TLS 1.2 are deprecated and usage may pose security risks.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**
  
    - Navigate to AWS EC2.
    - In the left navigation, select Load Balancers.
    - Select the load balancer > select Listeners.
    - Select the checkbox for the HTTPS listener and select Edit.
    - For Security policy, choose a security policy. See Security Policies for more information.
    - Click Update.
  
    **AWS CLI**
    
    - To update ELBv2 HTTPS listeners to use secure TLS protocol versions (1.2 and above):
    > aws elbv2 modify-listener \
    > --listener-arn <value> \
    > --protocol (string) \
    > --ssl-policy (string) \
    > --certificates (list)`,

  references: [
    'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-certificates.html#update-security-policy',
    'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies',
    'https://docs.aws.amazon.com/cli/latest/reference/elbv2/modify-listener.html',
  ],
  gql: `{
      queryawsAlb {
        id
        arn
        accountId
        __typename   
        listeners {
          settings {
            protocol
            sslPolicy
          }
        }
      }
    }`,
  resource: 'queryawsAlb[*]',
  severity: 'medium',
  conditions: {
    not: {
      path: '@.listeners',
      array_any: {
        and: [
          {
            path: '[*].settings.protocol',
            match: /^HTTPS.*$/,
          },
          {
            path: '[*].settings.sslPolicy',
            notIn: [
              'ELBSecurityPolicy-2016-08',
              'ELBSecurityPolicy-TLS-1-0-2015-04',
              'ELBSecurityPolicy-TLS-1-1-2017-01',
              'ELBSecurityPolicy-TLS-1-2-2017-01',
              'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
              'ELBSecurityPolicy-FS-2018-06',
              'ELBSecurityPolicy-FS-1-1-2019-08',
              'ELBSecurityPolicy-FS-1-2-2019-08',
              'ELBSecurityPolicy-FS-1-2-Res-2019-08',
              'ELBSecurityPolicy-2015-05',
              'ELBSecurityPolicy-FS-1-2-Res-2020-10',
            ],
          },
        ],
      },
    },
  },
}
