export default {
  id: 'aws-nist-800-53-rev4-4.6',  
  title: 'AWS NIST 4.6 SNS subscriptions should deny access via HTTP',
  
  description: 'SNS subscriptions should not use HTTP as the delivery protocol. To enforce encryption in transit, any subscription to an HTTP endpoint should use HTTPS instead.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  You cannot update an existing subscription to use HTTPS. You will need to create a new subscription using HTTPS and delete the existing subscription. Follow the instructions detailed here.
  
  To create a new subscription using HTTPS:
  
  - Sign in to the Amazon SNS console.
  
  - On the navigation panel, choose Subscriptions.
  
  - On the Subscriptions page, choose Create subscription.
  
  - On the Create subscription page, do the following:
  
    - Enter the topic ARN.
  
    - For Protocol, choose HTTPS.
  
    - For Endpoint, enter an HTTPS web server.
  
  - Confirm the subscription.
  
  To delete the HTTP subscription:
  
  - Sign in to the Amazon SNS console.
  
  - On the navigation panel, choose Subscriptions.
  
  - On the Subscriptions page, choose a confirmed subscription and then choose Delete.
  
  - In the Delete subscription dialog box, choose Delete.
  
  **AWS CLI**
  
  You cannot update an existing subscription to use HTTPS. You will need to create a new subscription using HTTPS and delete the existing subscription. Follow the instructions detailed here.
  
  To create a new subscription using HTTPS:
  
      aws sns subscribe \
          --topic-arn <ARN> \
          --protocol https \
          --notification-endpoint <URL beginning with https://>
  
  To delete the HTTP subscription:
  
      aws sns unsubscribe --subscription-arn <ARN>`,
  
  references: [
      'https://docs.aws.amazon.com/sns/latest/dg/sns-subscribe-https-s-endpoints-to-topic.html',
      'https://docs.aws.amazon.com/cli/latest/userguide/cli-services-sns.html',
      'https://docs.aws.amazon.com/cli/latest/reference/sns/subscribe.html',
      'https://docs.aws.amazon.com/cli/latest/reference/sns/unsubscribe.html',
  ], 
  gql: `{
    queryawsSns {
      id
      arn
      accountId
      __typename
      subscriptions {
        protocol  
        endpoint 
      }
    }
  }`,
  resource: 'queryawsSns[*]',
  severity: 'medium',
  conditions: { 
    not: {
      path: '@.subscriptions',
      array_any: {
        or: [
          {
            path: '[*].protocol',
            equal: 'http'
          },
          {
            path: '[*].endpoint',
            match: /^http:.*$/,
          },
        ],
      },
    },
  },
}
