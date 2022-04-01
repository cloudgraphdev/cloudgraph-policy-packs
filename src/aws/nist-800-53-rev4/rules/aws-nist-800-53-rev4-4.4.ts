export default {
  id: 'aws-nist-800-53-rev4-4.4',  
  title: 'AWS NIST 4.4 ELBv1 listener protocol should not be set to http',
  
  description: 'Communication from an ELB to EC2 instances should be encrypted to help prevent unauthorized access to data. To protect data in transit, ELB listener protocol should not be set to HTTP.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [EC2](https://console.aws.amazon.com/ec2/).
  - Follow the steps described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-add-or-delete-listeners.html#add-listener-console).
  
  **AWS CLI**
  
  List all of your load balancers to determine all of their names:
  
      aws elb describe-load-balancers
  
  Get a list of all SSL certificate ARNs available via AWS ACM:
  
      aws acm list-certificates --region <region>
  
  Also get a list of all SSL certificate ARNs available via AWS IAM:
  
      aws iam list-server-certificates
  
  Create a new HTTPS listener for any load balancer that needs it, using one of the SSL certificate ARNs previously listed:
  
      aws elb create-load-balancer-listeners --region <region> --load-balancer-name <load_balancer_name> --listeners Protocol=HTTPS, LoadBalancerPort=443, InstanceProtocol=HTTP, InstancePort=80, SSLCertificateId=<ssl_certificate_arn>`,
  
  references: [
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-add-or-delete-listeners.html',
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-add-or-delete-listeners.html#add-listener-console',
      'https://docs.aws.amazon.com/cli/latest/reference/elb/create-load-balancer-listeners.html',
  ],
  gql: `{
    queryawsElb {
      id
      arn
      accountId
      __typename
      listeners {
        loadBalancerProtocol
      }
    }
  }`,
  resource: 'queryawsElb[*]',
  severity: 'high',
  conditions: { 
    path: '@.listeners',
    array_all: {
      path: '[*].loadBalancerProtocol',
      equal: 'HTTPS'
    },  
  },
}
