export default {
  id: 'aws-nist-800-53-rev4-6.4',  
  title: 'AWS NIST 6.4 CloudTrail should have at least one CloudTrail trail set to a multi-region trail',
  
  description: 'As a best practice, AWS recommends creating a trail that applies to all regions in the AWS partition in which you are working. The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [CloudTrail](https://console.aws.amazon.com/cloudtrail).
  - In the left pane, select Trails.
  - Select the noncompliant trail.
  - Click the pencil icon next to Apply trail to all regions, and then choose Yes.
  - Click Save.
  
  **AWS CLI**
  
  To change a single-region trail to apply to all regions, replace MYTRAILNAME with your own trail name:
  
      aws cloudtrail update-trail --name MYTRAILNAME --is-multi-region-trail`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html',
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-update-trail.html#cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-examples-convert',
  ],  
  gql: `{
    queryawsAccount { 
      id
      __typename
      cloudtrail {
        isMultiRegionTrail
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  conditions: {  
    path: '@.cloudtrail',
    array_any: {
      path: '[*].isMultiRegionTrail',
      equal: 'Yes',
    },
  },
}
