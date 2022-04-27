export default {
  id: 'aws-nist-800-53-rev4-7.1',  
  title: 'AWS NIST 7.1 Alarm for denied connections in CloudFront logs should be configured',
  
  description: 'Alarms should be configured to alert users to denied connections to CloudFront distributions so users can investigate anomalous traffic.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [CloudFront](https://console.aws.amazon.com/cloudfront).
  - Under Reports & analytics, select Alarms.
  - Click Create Alarm.
  - In the Metric drop-down, select 4xx Error Rate.
  - In the Distribution drop-down, select your distribution.
  - In the Name of alarm field, provide a name for your alarm.
  - Determine if you wish to send a notification to an SNS topic and select the topic in the drop down menu.
  - Use the Whenever Sum of Requests drop down and text box to set your threshold.
  - Use the For at least text box and consecutive period(s) of drop-down to set your period.
  - Click Create Alarm.
  - Note you may also use [CloudWatch](https://console.aws.amazon.com/cloudwatch) to create alarms.
  
  **CLI Remediation Steps**
  
  Create a CloudWatch alarm to trigger on HTTP 4xx error codes to alert when client behavior is outside your expectations.
  
      aws cloudwatch put-metric-alarm --alarm-name <name> --evaluation-periods <number-of-samples> --comparison-operator <comparison-operator> --metric-name 4xxErrorRate --namespace "AWS/CloudFront" --period <evaluated-every-x> --threshold <your-expectation> --statistic <aggregated-by> --unit <unit-of-measure>
  
  Similarly, create a CloudWatch alarm to trigger on HTTP 5xx error codes when your system internal errors are outside your expectations.
  
      aws cloudwatch put-metric-alarm --alarm-name <name> --evaluation-periods <number-of-samples> --comparison-operator <comparison-operator> --metric-name 5xxErrorRate --namespace "AWS/CloudFront" --period <evaluated-every-x> --threshold <your-expectation> --statistic <aggregated-by> --unit <unit-of-measure>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/put-metric-alarm.html',
  ],
  gql: `{
    queryawsCloudfront {
      id
      arn
      accountId
      __typename
      cloudwatch {
       metric
      }
    }
  }`,
  resource: 'queryawsCloudfront[*]',
  severity: 'medium',
  conditions: {
    jq: '.cloudwatch | map(select(.metric == "4xxErrorRate" or .metric == "5xxErrorRate")) | { "twoOrMore" : (length >= 2) }',
    path: '@',
    and: [
      {
        path: '@.twoOrMore',
        equal: true,
      },
    ],
  }
}
