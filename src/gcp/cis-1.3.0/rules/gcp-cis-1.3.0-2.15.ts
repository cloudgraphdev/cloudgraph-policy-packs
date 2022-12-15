export default {
  id: 'gcp-cis-1.3.0-2.15',
  title:
    'GCP CIS 2.15  Ensure \'Access Approval\' is \'Enabled\'',
  description: `GCP Access Approval enables you to require your organizations' explicit approval
  whenever Google support try to access your projects. You can then select users within your
  organization who can approve these requests through giving them a security role in IAM.
  All access requests display which Google Employee requested them in an email or Pub/Sub
  message that you can choose to Approve. This adds an additional control and logging of
  who in your organization approved/denied these requests.`,
  audit: `**Determine if Access Transparency is Enabled**

  1. From the Google Cloud Home, click on the Navigation hamburger menu in the top left. Hover over the IAM & Admin Menu. Select settings in the middle of the column that opens.
  2. The status should be "Enabled' under the heading *Access Transparency*

  **Enable Access Transparency**

  1. From the Google Cloud Home, click on the Navigation hamburger menu in the top left. Hover over the *IAM & Admin* Menu. Select *settings* in the middle of the column that opens.
  2. Click the blue button labeled Enable *Access Transparency for Organization*

  **Determine if Access Approval is Enabled**

  1. From the Google Cloud Home, within the project you wish to check, click on the Navigation hamburger menu in the top left. Hover over the *Security* Menu. Select *Access Approval* in the middle of the column that opens.
  2. The status will be displayed here. If you see a screen saying you need to enroll in Access Approval, it is not enabled.

  **From CLI:

  Determine if Access Approval is Enabled**

  1. From within the project you wish to audit, run the following command.

        gcloud access-approval settings get

  2. The status will be displayed in the output.`,

  rationale: `Controlling access to your information is one of the foundations of information security.
  Google Employees do have access to your organizations' projects for support reasons. With
  Access Approval, organizations can then be certain that their information is accessed by
  only approved Google Personnel.`,
  remediation: `**From Console:**

  1. From the Google Cloud Home, within the project you wish to enable, click on the Navigation hamburger menu in the top left. Hover over the *Security* Menu. Select *Access Approval* in the middle of the column that opens.
  2. The status will be displayed here. On this screen, there is an option to click *Enroll*. If
  it is greyed out and you see an error bar at the top of the screen that says *Access Transparency is not enabled* please view the corresponding reference within this section to enable it.
  3. In the second screen click *Enroll*.

  **Grant an IAM Group or User the role with permissions to Add Users to be Access Approval message Recipients**

  1. From the Google Cloud Home, within the project you wish to enable, click on the Navigation hamburger menu in the top left. Hover over the *IAM and Admin*. Select *IAM* in the middle of the column that opens.
  2. Click the blue button the says *+add* at the top of the screen.
  3. In the *principals* field, select a user or group by typing in their associated email address.
  4. Click on the role field to expand it. In the filter field enter *Access Approval Approver* and select it.
  5. Click *save*.

  **Add a Group or User as an Approver for Access Approval Requests**

  1. As a user with the *Access Approval Approver* permission, within the project where you wish to add an email address to which request will be sent, click on the Navigation hamburger menu in the top left. Hover over the *Security* Menu. Select *Access Approval* in the middle of the column that opens.
  2. Click *Manage Settings*
  3. Under *Set up approval notifications*s, enter the email address associated with a Google Cloud User or Group you wish to send Access Approval requests to. All future access approvals will be sent as emails to this address.

  **From CLI:**

  1. To update all services in an entire project, run the following command from an account that has permissions as an 'Approver for Access Approval Requests'

        gcloud access-approval settings update --project=<project name> --
        enrolled_services=all --notification_emails='<email recipient for access
        approval requests>@<domain name>'

  **Default Value:**

  By default Access Approval and its dependency of Access Transparency are not enabled.`,
  references: [
    'https://cloud.google.com/cloud-provider-access-management/accessapproval/docs',
    'https://cloud.google.com/cloud-provider-access-management/accessapproval/docs/overview',
    'https://cloud.google.com/cloud-provider-access-management/accessapproval/docs/quickstart-custom-key',
    'https://cloud.google.com/cloud-provider-access-management/accessapproval/docs/supported-services',
    'https://cloud.google.com/cloud-provider-access-management/accessapproval/docs/view-historical-requests',
  ],
  gql: `{
    querygcpAsset {
      id
      __typename
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  check: ({ resource }: any) => {
    const { assets } = resource
    return !!assets
  },
}
