/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

export default {
  id: 'gcp-cis-1.3.0-1.18',
  title: 'GCP CIS 1.18 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager',
  description:
    'Google Cloud Functions allow you to host serverless code that is executed when an event is triggered, without the requiring the management a host operating system. These functions can also store environment variables to be used by the code that may contain authentication or other information that needs to remain confidential.',
  audit: `Determine if Confidential Information is Stored in your Functions in Cleartext

  **From Console:**

  1. Log in to the Google Cloud Web Portal (https://console.cloud.google.com/)
  2. Within the project you wish to audit, select the Navigation hamburger menu in the top left. Scroll down to under the heading 'Serverless', then select 'Cloud Functions'
  3. Click on a function name from the list
  4. Open the Variables tab and you will see both buildEnvironmentVariables and environmentVariables
  5. Review the variables whether they are secrets
  6. Repeat step 3-5 until all functions are reviewed

  **From Command Line:**

  1. To view a list of your cloud functions run

        cloud functions list

  2. For each cloud function in the list run the following command.

        gcloud functions describe <function_name>

  3. Review the settings of the buildEnvironmentVariables and environmentVariables. Determine if this is data that should not be publicly accessible.

  Determine if Secret Manager API is 'Enabled' for your Project
  
  **From Console**

  1. Within the project you wish to audit, select the Navigation hamburger menu in the top left. Hover over 'APIs & Services' to under the heading 'Serverless', then select 'Enabled APIs & Services' in the menu that opens up.
  2. Click the button '+ Enable APIS and Services'
  3. In the Search bar, search for 'Secret Manager API' and select it.
  4. If it is enabled, the blue box that normally says 'Enable' will instead say 'Manage'.

  **From Command Line:**

  1. Within the project you wish to audit, run the following command.

        gcloud services list

  2. If 'Secret Manager API' is in the list, it is enabled.
  `,
  rationale:
    'It is recommended to use the Secret Manager, because environment variables are stored unencrypted, and accessible for all users who have access to the code.',
  remediation: `Enable Secret Manager API for your Project

  **From Console:**

  1. Within the project you wish to enable, select the Navigation hamburger menu in the top left. Hover over 'APIs & Services' to under the heading 'Serverless', then select 'Enabled APIs & Services' in the menu that opens up.
  2. Click the button '+ Enable APIS and Services'
  3. In the Search bar, search for 'Secret Manager API' and select it.
  4. Click the blue box that says 'Enable'.

  **From Command Line:**

  1. Within the project you wish to enable the API in, run the following command.

        gcloud services enable Secret Manager API
  
  Reviewing Environment Variables That Should Be Migrated to Secret Manager

  **From Console:**

  1. Log in to the Google Cloud Web Portal (https://console.cloud.google.com/)
  2. Go to Cloud Functions
  3. Click on a function name from the list
  4. Click on Edit and review the Runtime environment for variables that should be secrets. Leave this list open for the next step.

  **From Command Line:**

  1. To view a list of your cloud functions run
    
        cloud functions list

  2. For each cloud function run the following command.

        gcloud functions describe <function_name>

  3. Review the settings of the buildEnvironmentVariables and environmentVariables. Keep this information for the next step.

  Migrating Environment Variables to Secrets within the Secret Manager

  **From Console:**

  1. Go to the Secret Manager page in the Cloud Console.
  2. On the Secret Manager page, click Create Secret.
  3. On the Create secret page, under Name, enter the name of the Environment Variable you are replacing. This will then be the Secret Variable you will reference in your code.
  4. You will also need to add a version. This is the actual value of the variable that will be referenced from the code. To add a secret version when creating the initial secret, in the Secret value field, enter the value from the Environment Variable you are replacing.
  5. Leave the Regions section unchanged.
  6. Click the Create secret button.
  7. Repeat for all Environment Variables

  **From Command Line**

  1. Run the following command with the Environment Variable name you are replacing in the *<secret-id>*. It is most secure to point this command to a file with the Environment Variable value located in it, as if you entered it via command line it would show up in your shell’s command history.

        gcloud secrets create <secret-id> --data-file="/path/to/file.txt"

  Granting your Runtime's Service Account Access to Secrets

  **From Console**

  1. Within the project containing your runtime login with account that has the 'roles/secretmanager.secretAccessor' permission.
  2. Select the Navigation hamburger menu in the top left. Hover over 'Security' to under the then select 'Secret Manager' in the menu that opens up.
  3. Click the name of a secret listed in this screen.
  4. If it is not already open, click Show Info Panel in this screen to open the panel.
  5.In the info panel, click Add principal.
  6.In the New principals field, enter the service account your function uses for its identity. (If you need help locating or updating your runtime's service account, please see the 'docs/securing/function-identity#runtime_service_account' reference.)
  5. In the Select a role dropdown, choose Secret Manager and then Secret Manager Secret Accessor.

  **From Command Line**

  As of the time of writing, using Google CLI to list Runtime variables is only in beta. Because this is likely to change we are not including it here.

  Modifying the Code to use the Secrets in Secret Manager

  **From Console**

  This depends heavily on which language your runtime is in. For the sake of the brevity of this recommendation, please see the '/docs/creating-and-accessing-secrets#access' reference for language specific instructions.

  **From Command Line**

  This depends heavily on which language your runtime is in. For the sake of the brevity of this recommendation, please see the' /docs/creating-and-accessing-secrets#access' reference for language specific instructions.

  Deleting the Insecure Environment Variables Be certain to do this step last. Removing variables from code actively referencing them will prevent it from completing successfully.

  **From Console**

  1. Select the Navigation hamburger menu in the top left. Hover over 'Security' then select 'Secret Manager' in the menu that opens up.
  2. Click the name of a function. Click Edit.
  3. Click Runtime, build and connections settings to expand the advanced configuration options.
  4. Click 'Security’. Hover over the secret you want to remove, then click 'Delete'.
  5. Click Next. Click Deploy. The latest version of the runtime will now reference the secrets in Secret Manager.

  **From Command Line**

        gcloud functions deploy <Function name>--remove-env-vars <env vars>

  If you need to find the env vars to remove, they are from the step where ‘gcloud functions describe *<function_name>*’ was run.

  **Default Value:**
  
  By default Secret Manager is not enabled.
  `,
  references: [
    ['https://cloud.google.com/functions/docs/configuring/env-var#managing_secrets'],
    ['https://cloud.google.com/secret-manager/docs/overview'],
  ],
  severity: 'unknown',
}
