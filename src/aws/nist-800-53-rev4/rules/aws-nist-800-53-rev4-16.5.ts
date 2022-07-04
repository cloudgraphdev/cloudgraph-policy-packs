export default {
  id: 'aws-nist-800-53-rev4-16.5',
  title:
    'AWS NIST 16.5 ELB HTTPS listeners should use secure TLS protocol versions (1.2 and above)',

  description:
    'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible. Versions prior to TLS 1.2 are deprecated and usage may pose security risks.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**
    - Navigate to AWS EC2.
    - In the left navigation, select Load Balancers.
    - Select the load balancer > select Listeners.
    - Under SSL Certificate, select Change.
    - Select your Certificate type from the following:
      - Choose a certificate from ACM. Refer to What Is AWS Certificate Manager? for more information.
      - Choose a certificate from IAM. Refer to Managing server certificates in IAM for more information.
      - Upload a certificate to IAM. Refer to How can I upload and import an SSL certificate to AWS Identity and Access Management (IAM)?
    - Click Save.

    **AWS CLI**

    Select your Certificate type from the following:
    **To replace an SSL certificate with a certificate provided by ACM:**
    - Use the following request-certificate command to request a new certificate:
      > aws acm request-certificate --domain-name www.example.com
    - Use the following set-load-balancer-listener-ssl-certificate command to set the certificate:
      > aws elb set-load-balancer-listener-ssl-certificate --load-balancer-name my-load-balancer --load-balancer-port 443 --ssl-certificate-id arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012
    **To replace an SSL certificate with a certificate uploaded to IAM:**
    - If you have an SSL certificate but have not uploaded it, refer to Uploading a server certificate in the IAM User Guide.
    - Use the following get-server-certificate command to get the ARN of the certificate:
      > aws iam get-server-certificate --server-certificate-name my-new-certificate
    - Use the following set-load-balancer-listener-ssl-certificate command to set the certificate:
      > aws elb set-load-balancer-listener-ssl-certificate --load-balancer-name my-load-balancer --load-balancer-port 443 --ssl-certificate-id arn:aws:iam::123456789012:server-certificate/my-new-certificate`,

  references: [
    'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-update-ssl-cert.html#us-update-lb-SSLcert-console',
    'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-update-ssl-cert.html#us-update-lb-SSLcert-cli',
  ],
  gql: `{
      queryawsElb {
        id
        arn
        accountId
        __typename
        listeners {
          loadBalancerProtocol
          sslCertificateId
        }
      }
    }`,
  resource: 'queryawsElb[*]',
  severity: 'medium',
  conditions: {
    not: {
      path: '@.listeners',
      array_any: {
        and: [
          {
            path: '[*].loadBalancerProtocol',
            equal: 'HTTPS',
          },
          {
            path: '[*].sslCertificateId',
            isEmpty: true,
          },
        ],
      },
    },
  },
}
