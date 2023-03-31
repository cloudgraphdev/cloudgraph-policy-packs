/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

export default {
  id: 'aws-cis-1.5.0-4.16',  
  title: 'AWS CIS 4.16 Ensure AWS Security Hub is enabled',
  
  description: 'Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products.',
  
  audit: `The process to evaluate AWS Security Hub configuration per region

  **From Console:**
  1. Sign in to the AWS Management Console and open the AWS Security Hub console at https://console.aws.amazon.com/securityhub/.
  2. On the top right of the console, select the target Region.
  3. If presented with the Security Hub > Summary page then Security Hub is set-up for the selected region.
  4. If presented with Setup Security Hub or Get Started With Security Hub - follow the online instructions.
  5. Repeat steps 2 to 4 for each region.`,
  
  rationale: 'AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices - enabling you to quickly assess the security posture across your AWS accounts.',
  
  remediation: `To grant the permissions required to enable Security Hub, attach the Security Hub managed policy AWSSecurityHubFullAccess to an IAM user, group, or role.
  
  Enabling Security Hub

  **From Console:**

  1. Use the credentials of the IAM identity to sign in to the Security Hub console.
  2. When you open the Security Hub console for the first time, choose Enable AWS Security Hub.
  3. On the welcome page, Security standards list the security standards that Security Hub supports.
  4. Choose Enable Security Hub.
  
  **From Command Line:**

  1. Run the enable-security-hub command. To enable the default standards, include *--enable-default-standards*.

    aws securityhub enable-security-hub --enable-default-standards

  2. To enable the security hub without the default standards, include *--no-enable-default-standards*.

    aws securityhub enable-security-hub --no-enable-default-standards`,
  
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-get-started.html',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html#securityhub-enable-api',
    'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/securityhub/enable-security-hub.html',
  ],
  gql: `{
    queryawsAccount {
      id
      __typename
      securityHub {
        id
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  check: ({ resource }: any): any => {
    return resource.securityHub && resource.securityHub.length !== 0
  },
}
