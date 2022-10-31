export default {
  id: 'aws-cis-1.5.0-2.1.3',  
  title: 'AWS CIS 2.1.3 Ensure MFA Delete is enable on S3 buckets',

  description: 'Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.',

  audit: `Perform the steps below to confirm MFA delete is configured on an S3 Bucket

  **From Console:**

  1. Login to the S3 console at https://console.aws.amazon.com/s3/
  2. Click the _Check_ box next to the Bucket name you want to confirm
  3. In the window under _Properties_
  4. Confirm that Versioning is _Enabled_
  5. Confirm that MFA Delete is _Enabled_

  **From Command Line:**

  1.  Run the get-bucket-versioning

          aws s3api get-bucket-versioning --bucket my-bucket

      Output example:

          <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Status>Enabled</Status>
              <MfaDelete>Enabled</MfaDelete>
          </VersioningConfiguration>

  If the Console or the CLI output does not show Versioning and MFA Delete enabled refer to the remediation below.`,

  rationale: 'Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.',

  remediation: `Perform the steps below to enable MFA delete on an S3 bucket.  
  Note:  
  -You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.  
  -You must use your 'root' account to enable MFA Delete on S3 buckets.

  **From Command line:**

  1.  Run the s3api put-bucket-versioning command

          aws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled`,

  references: [
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
    'https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html',
    'https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html',
  ],
  gql: `{
      queryawsS3 {
         id
         arn
         accountId
         __typename
         versioning
         mfa
       }
     }`,
  resource: 'queryawsS3[*]',
  severity: 'high',
  conditions: {
    and: [
      {
         path: '@.versioning',
        equal: 'Enabled',
      },
      {
        path: '@.mfa',
        equal: 'Enabled',
      },
    ],
  },
}