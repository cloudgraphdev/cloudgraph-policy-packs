export default {
    id: 'aws-nist-800-53-rev4-6.9',  
    title: 'AWS NIST 6.9 Load balancer access logging should be enabled',
    
    description: 'Access logs record information about every HTTP and TCP request a load balancer processes. Access logging should be enabled in order to analyze statistics, diagnose issues, and retain data for regulatory or legal purposes.',
    
    audit: '',
  
    rationale: '',
    
    remediation: `**AWS Console**
    
    The steps are different for classic load balancers (ELB) and next generation load balancers (ELBv2), such as application load balancers and network load balancers. See the [product comparison](https://aws.amazon.com/elasticloadbalancing/features/#Product_comparisons) for more information.
    
    For classic load balancers, follow these steps:
    
    - Navigate to [EC2](https://console.aws.amazon.com/ec2/).
    - In the navigation pane, choose Load Balancers.
    - Select your load balancer.
    - On the Description tab, choose Configure access logs.
    - Check Enable Access Logs.
    - Specify an interval in the Interval drop-down.
    - Provide a name for your S3 bucket and check Create this location for me or provide the name for a bucket which already exists.
    - Click Save.
    
    For next generation load balancers, follow these steps:
    
    - Navigate to [EC2](https://console.aws.amazon.com/ec2/).
    - In the navigation pane, choose Load Balancers.
    - Select your load balancer.
    - On the Description tab, choose Edit attributes.
    - On the Edit load balancer attributes page, Choose Configure access logs.
    - Check Enable for Access Logs.
    - Provide a name for your S3 bucket and check Create this location for me or provide the name for a bucket which already exists.
    - Click Save.
    
    **AWS CLI**
    
    The steps are different for classic load balancers and next generation load balancers.
    
    For classic load balancers, follow these steps:
    
    The steps are different for classic load balancers and next generation load balancers.
    
    For classic load balancers, follow these steps:
    
    Create a .json file that enables Elastic Load Balancing to capture and deliver logs every 60 minutes to an S3 bucket that you have created for the logs:
    
        {
            "AccessLog": {
                "Enabled": true,
                "S3BucketName": "my-loadbalancer-logs",
                "EmitInterval": 60,
                "S3BucketPrefix": "my-app"
            }
        }
    
    To enable access logs for your load balancer:
    
        aws elb modify-load-balancer-attributes --load-balancer-name <my-loadbalancer> --load-balancer-attributes file://my-json-file.json
    
    For next generation load balancers, follow these steps:
    
    Create a .json file that enables Elastic Load Balancing to capture and deliver logs to an S3 bucket that you have created for the logs:
    
        {
            "LoadBalancerArn": "<my-loadbalancer-arn>",
            "Attributes": [
                {
                    "Key": "access_logs.s3.enabled",
                    "Value": "true"
                },
                {
                    "Key": "access_logs.s3.bucket",
                    "Value": "my-loadbalancer-logs"
                },
                {
                    "Key": "access_logs.s3.prefix",
                    "Value": "my-app"
                }
            ]
        }
    
    To enable access logs for your load balancer:
    
        aws elbv2 modify-load-balancer-attributes --cli-input-json file://my-json-file.json`,
    
    references: [
        'https://aws.amazon.com/elasticloadbalancing/features/#Product_comparisons',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html',
        'https://docs.aws.amazon.com/cli/latest/reference/elb/modify-load-balancer-attributes.html',
        'https://docs.aws.amazon.com/cli/latest/reference/elbv2/modify-load-balancer-attributes.html',
    ], 
  severity: 'medium',
  queries: [
    {
      gql: `{
        queryawsElb {
          id
          arn
          accountId
          __typename
          accessLogs
        }
      }`,
      resource: 'queryawsElb[*]',
      conditions: {
        path: '@.accessLogs',
        equal: 'Enabled',
      },
    },
    {
      gql: `{
          queryawsAlb {
          id
          arn
          accountId
          __typename
          accessLogsEnabled
        }
      }`,
      resource: 'queryawsAlb[*]',
      conditions: {
        path: '@.accessLogsEnabled',
        equal: 'Yes',
      },
    },
  ],
}
