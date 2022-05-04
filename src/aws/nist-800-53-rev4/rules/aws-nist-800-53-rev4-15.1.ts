export default {
  id: 'aws-nist-800-53-rev4-15.1',  
  title: 'AWS NIST 15.1 ECS task definitions should not use the root user',
  
  description: `Running container processes with a non-root user limits vectors by which the account can be compromised. It also encourages the creation and use of role-based accounts that are least privileged.
  
  The **user** property must be set to a non-root user for each **ContainerDefinition** within the task definition. For more information about the **user** property, see [ContainerDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html) in the ECS API Reference.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, change the container definitions to not use the root user and click Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see [Updating a service](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html).
  
  **CLI Remediation Steps**
  
  Step 1 is to set the user in the image:
  
  The Dockerfile for each container image contains the information below:
  
      USER <username or ID>
  
  To create a user in the container:
  
      RUN useradd -d /home/username -m -s /bin/bash username <USER> username
  
  Step 2 is to have a non-root user available in your image and you’ll need to specify it in the container definition:
  
  To register a new revision of the task definition with a corrected container definition:
  
      aws ecs register-task-definition
      --family <value>
      [--task-role-arn <value>]
      [--execution-role-arn <value>]
      [--network-mode <value>]
      --container-definitions <value>
      [--volumes <value>]
      [--placement-constraints <value>]
      [--requires-compatibilities <value>]
      [--cpu <value>]
      [--memory <value>]
      [--tags <value>]
      [--pid-mode <value>]
      [--ipc-mode <value>]
      [--proxy-configuration <value>]
      [--inference-accelerators <value>]
      [--cli-input-json | --cli-input-yaml]
      [--generate-cli-skeleton <value>]
  
  Update the service to use the new task definition:
  
      aws ecs update-service
      [--cluster <value>]
      --service <value>
      [--desired-count <value>]
      [--task-definition <value>]
      [--capacity-provider-strategy <value>]
      [--deployment-configuration <value>]
      [--network-configuration <value>]
      [--placement-constraints <value>]
      [--placement-strategy <value>]
      [--platform-version <value>]
      [--force-new-deployment | --no-force-new-deployment]
      [--health-check-grace-period-seconds <value>]
      [--cli-input-json | --cli-input-yaml]
      [--generate-cli-skeleton <value>]`,
  
  references: [
      'https://github.com/docker/docker/issues/2918',
      'https://github.com/docker/docker/pull/4572',
      'https://github.com/docker/docker/issues/7906',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
  ],
  gql: `{
    queryawsEcsTaskDefinition {
      id
      arn
      accountId
       __typename
      containerDefinitions {
        user
      }
    }
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'high',
  conditions: {  
    not: {
      path: '@.containerDefinitions',
      array_any: {
        path: '[*].user',
        equal: 'root',
      },
    },
  },
}
