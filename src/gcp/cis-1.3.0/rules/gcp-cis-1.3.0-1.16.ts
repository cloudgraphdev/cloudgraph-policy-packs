/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

export default {
  id: 'gcp-cis-1.3.0-1.16',
  title: 'GCP CIS 1.16 Ensure Essential Contacts is Configured for Organization',
  description:
    'It is recommended that Essential Contacts is configured to designate email addresses for Google Cloud services to notify of important technical or security information.',
  audit: `**From Console:**
  
  1. Go to Essential Contacts by visiting https://console.cloud.google.com/iam-admin/essential-contacts
  2. Make sure the organization appears in the resource selector at the top of the page. The resource selector tells you what project, folder, or organization you are currently managing contacts for.
  3. Ensure that appropriate email addresses are configured for each of the following notification categories:

    - Legal
    - Security
    - Suspension
    - Technical
    - Technical Incidents
  
  Alternatively, appropriate email addresses can be configured for the All notification category to receive all possible important notifications.

  **From Command Line:**

  1. To list all configured organization Essential Contacts run a command:

          gcloud essential-contacts list --organization=<ORGANIZATION_ID>

  2. Ensure at least one appropriate email address is configured for each of the following notification categories:

    - LEGAL
    - SECURITY
    - SUSPENSION
    - TECHNICAL
    - TECHNICAL_INCIDENTS
  
  Alternatively, appropriate email addresses can be configured for the ALL notification category to receive all possible important notifications.
  `,
  rationale:
    'Many Google Cloud services, such as Cloud Billing, send out notifications to share important information with Google Cloud users. By default, these notifications are sent to members with certain Identity and Access Management (IAM) roles. With Essential Contacts, you can customize who receives notifications by providing your own list of contacts.',
  remediation: `**From Console:**
  1. Go to Essential Contacts by visiting https://console.cloud.google.com/iam-admin/essential-contacts
  2. Make sure the organization appears in the resource selector at the top of the page. The resource selector tells you what project, folder, or organization you are currently managing contacts for.
  3. Click +Add contact
  4. In the Email and Confirm Email fields, enter the email address of the contact.
  5. From the Notification categories drop-down menu, select the notification categories that you want the contact to receive communications for.
  6. Click Save

  **From Command Line:**

  1. To add an organization Essential Contacts run a command:

          gcloud essential-contacts create --email="<EMAIL>" \
          --notification-categories="<NOTIFICATION_CATEGORIES>" \
          --organization=<ORGANIZATION_ID>

  **Default Value:**

    By default, there are no Essential Contacts configured.

    In the absence of an Essential Contact, the following IAM roles are used to identify users to
    notify for the following categories:

      • Legal: roles/billing.admin
      • Security: roles/resourcemanager.organizationAdmin
      • Suspension: roles/owner
      • Technical: roles/owner
      • Technical Incidents: roles/owner
  `,
  references: [
    'https://cloud.google.com/resource-manager/docs/managing-notification-contacts',
  ],
  gql: `{
    querygcpEssentialContact {
      id
      __typename
      notificationCategorySubscriptions
      email
    }
  }`,
  resource: 'querygcpEssentialContact[1]',
  severity: 'unknown',

  check: ({ data }: any): boolean => {
    const requiredCategories = ['LEGAL', 'SECURITY', 'SUSPENSION', 'TECHNICAL', 'TECHNICAL_INCIDENTS']
    const categoryAll = 'ALL'

    const subscribedCategories = data.querygcpEssentialContact
      .filter((obj: any) => !('@' in obj))
      .flatMap(({notificationCategorySubscriptions}: any) => notificationCategorySubscriptions)
      
    const result = requiredCategories.every((category: any) => subscribedCategories.includes(category))

    return result || subscribedCategories.includes(categoryAll)
  }
}
