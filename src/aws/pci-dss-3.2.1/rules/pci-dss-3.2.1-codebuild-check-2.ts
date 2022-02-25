export default {
  id: 'aws-pci-dss-3.2.1-codebuild-check-2',
  title:
    'CodeBuild Check 2: CodeBuild project environment variables should not contain clear text credentials',
  description:
    'This control checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.',
  rationale: `**PCI DSS 8.2.1: Using strong cryptography, render all authentication credentials (such as passwords/phrases) unreadable during transmission and storage on all system components.**

  You can use CodeBuild in your PCI DSS environment to compile your source code, runs unit tests, or produce artifacts that are ready to deploy. If you do, never store the authentication credentials AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in clear text.

  Using environmental variables to store credentials in your CodeBuild project may violate the requirement to use strong cryptography to render authentication credentials unreadable.`,
  remediation: `To reference sensitive data in CodeBuild runtime using Environmental variables, use the following procedures.

  **To remove an Environmental Variable**

  1. Open the CodeBuild console at https://console.aws.amazon.com/codebuild/.
  2. Expand **Build**, choose **Build project**, and then choose the build project that contains plaintext credentials.
  3. From **Edit**, choose **Environment**.
  4. Expand **Additional configuration** and then scroll to **Environment variables**.
  5. Choose **Remove** next to the environment variable.
  6. Choose **Update environment**.

  **To store sensitive values in the Amazon EC2 Systems Manager Parameter Store and then retrieve them from your build spec**

  1. Open the CodeBuild console at https://console.aws.amazon.com/codebuild/.
  2. Expand **Build**, choose **Build project**, and then choose your build project that contains plaintext credentials.
  3. From **Edit**, choose **Environment**.
  4. Expand **Additional configuration** and then scroll to **Environment variables**.
  5. In AWS Systems Manager, create a Systems Manager parameter that contains your sensitive data. For instructions on how to do this, refer to the tutorial in the [AWS Systems Manager User Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-console.html).
  6. After you create the parameter, copy the parameter name.
  7. Back in the CodeBuild console, choose **Create environmental variable**.
  8. For **name**, enter the name of your variable as it appears in your build spec.
  9. For **value**, paste in the name of your parameter.
  10. From **type**, choose **Parameter**.
  11. Choose **Remove** next to your noncompliant environmental variable that contains plaintext credentials.
  12. Choose **Update environment**.

  See the information on environment variables in build environments in the [AWS CodeBuild User Guide](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-console.html',
    'https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html',
  ],
  gql: `{
    queryawsCodebuild {
      id
      arn
      accountId
      __typename
      environment {
        environmentVariables {
          type
          name
        }
      }
    }
  }`,
  resource: 'queryawsCodebuild[*]',
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.environment.environmentVariables',
        isEmpty: true
      },
      {
        path: '@.environment.environmentVariables',
        array_any: {
          and: [
            {
              and: [
                { path: '[*].type', equal: 'PLAINTEXT' },
                { path: '[*].name', mismatch: /^ACCESS_KEY.*$/ },
              ],
            },
            {
              and: [
                { path: '[*].type', equal: 'PLAINTEXT' },
                { path: '[*].name', mismatch: /^SECRET.*$/ },
              ],
            },
            {
              and: [
                { path: '[*].type', equal: 'PLAINTEXT' },
                { path: '[*].name', mismatch: /^PASSWORD.*$/ },
              ],
            },
          ],
        },
      }
    ]

  },
}
