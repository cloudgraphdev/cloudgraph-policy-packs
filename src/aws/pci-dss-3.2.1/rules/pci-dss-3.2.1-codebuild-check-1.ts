export default {
  id: 'aws-pci-dss-3.2.1-codebuild-check-1',
  title:
    'CodeBuild Check 1: CodeBuild GitHub or Bitbucket source repository URLs should use OAuth',
  description:
    'This control checks whether the GitHub or Bitbucket source repository URL contains either personal access tokens or a user name and password.',
  rationale: `**PCI DSS 8.2.1: Using strong cryptography, render all authentication credentials (such as passwords/phrases) unreadable during transmission and storage on all system components.**

  You can use CodeBuild in your PCI DSS environment to compile your source code, run unit tests, or produce artifacts that are ready to deploy. If you do, your authentication credentials should never be stored or transmitted in clear text or appear in the repository URL.

  You should use OAuth instead of personal access tokens or a user name and password to grant authorization for accessing GitHub or Bitbucket repositories. This is a method to use strong cryptography to render authentication credentials unreadable.`,
  remediaton: `**To remove basic authentication / (GitHub) Personal Access Token from CodeBuild Project Source**

  1. Open the CodeBuild console at https://console.aws.amazon.com/codebuild/.
  2. Select your Build project that contains personal access tokens or a user name and password.
  3. From **Edit**, choose **Source**.
  4. Choose **Disconnect from GitHub / Bitbucket**.
  5. Choose **Connect using OAuth** and then choose **Connect to GitHub / Bitbucket**.
  6. In the message displayed by your source provider, authorize as appropriate.
  7. Reconfigure your **Repository URL** and **additional configuration** settings, as needed.
  9. Choose **Update source**.
  To see CodeBuild use case-based samples, see the [AWS CodeBuild User Guide](https://docs.aws.amazon.com/codebuild/latest/userguide/use-case-based-samples.html).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/codebuild/latest/userguide/use-case-based-samples.html',
  ],
  gql: `{
    queryawsCodebuild {
      id
      arn
      accountId
      __typename
       source {
        type
        auth {
          type
        }
      }
    }
  }`,
  resource: 'queryawsCodebuild[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        or: [
          {
            path: '@.source.type',
            equal: 'BITBUCKET',
          },
          {
            path: '@.source.type',
            equal: 'GITHUB',
          },
        ],
      },
      {
        path: '@.source.auth.type',
        equal: 'OAUTH',
      },
    ],
  },
}
