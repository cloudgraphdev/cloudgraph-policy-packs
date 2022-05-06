// AWS CIS 1.4.0 Rule equivalent 1.19
export default {
  id: 'aws-cis-1.3.0-1.19',  
  title: 'AWS CIS 1.19 Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed',
  
  description: 'To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You can use ACM or IAM to store and deploy server certificates. Use IAM as a certificate manager only when you must support HTTPS connections in a region that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console.',
  
  audit: `**From Console:**
  Getting the certificates expiration information via AWS Management Console is not currently supported.
  To request information about the SSL/TLS certificates stored in IAM via the AWS API use the Command Line Interface (CLI).
  
  **From Command Line:**
  Run list-server-certificates command to list all the IAM-stored server certificates:
  
          aws iam list-server-certificates
  
  The command output should return an array that contains all the SSL/TLS certificates currently stored in IAM and their metadata (name, ID, expiration date, etc):
  
          { 
                  "ServerCertificateMetadataList": [
                          {
                                  "ServerCertificateId": "EHDGFRW7EJFYTE88D",
                                  "ServerCertificateName": "MyServerCertificate",
                                  "Expiration": "2018-07-10T23:59:59Z",
                                  "Path": "/",
                                  "Arn": "arn:aws:iam::012345678910:server-certificate/MySSLCertificate",
                                  "UploadDate": "2018-06-10T11:56:08Z"
                          }
                  ] 
          }
  
  Verify the ServerCertificateName and Expiration parameter value (expiration date) for each SSL/TLS certificate returned by the list-server-certificates command and determine if there are any expired server certificates currently stored in AWS IAM. If so, use the AWS API to remove them.
  If this command returns:
  
          { { "ServerCertificateMetadataList": [] }
  
  This means that there are no expired certificates, It DOES NOT mean that no certificates exist.`,
  
  rationale: 'Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application/website behind the ELB. As a best practice, it is recommended to delete expired certificates.',
  
  remediation: `**From Console:**
  Removing expired certificates via AWS Management Console is not currently supported. To delete SSL/TLS certificates stored in IAM via the AWS API use the Command Line Interface (CLI).
  **From Command Line:**
  To delete Expired Certificate run following command by replacing <CERTIFICATE_NAME> with the name of the certificate to delete:
  
          aws iam delete-server-certificate --server-certificate-name <CERTIFICATE_NAME>
  
  When the preceding command is successful, it does not return any output.`,
  
  references: [
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html',
    'https://docs.aws.amazon.com/cli/latest/reference/iam/delete-server-certificate.html',
  ],
  gql: `{
    queryawsIamServerCertificate {
      id
      arn
      accountId
      __typename
      expiration
    }
  }`,
  resource: 'queryawsIamServerCertificate[*]',
  severity: 'high',
  conditions: {
    value: { daysDiff: {}, path: '@.expiration' },
    greaterThanInclusive: 1,
  },
}