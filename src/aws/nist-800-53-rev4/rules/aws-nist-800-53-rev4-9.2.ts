export default {
  id: 'aws-nist-800-53-rev4-9.2',  
  title: 'AWS NIST 9.2 ECS task definitions should mount the container’s root filesystem as read-only',
  
  description: `Mounting the container’s root filesystem as read-only prevents any writes to the container’s root filesystem at container runtime and enforces the principle of immutable infrastructure. This reduces security attack vectors since the container instance’s filesystem cannot be tampered with or written to unless it has explicit read-write permissions on its filesystem folder and directories.
  
  The **readonlyRootFilesystem** property must be set to **true** for each container definition within the task definition. For more information about the **readonlyRootFilesystem** property, see [ContainerDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html) in the ECS API reference.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  references: [
    'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
    'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
    'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
    'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
],
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory limits, or port mappings), select the container, make the changes, and then choose Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see [Updating a service](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html).
  
  **CLI Remediation Steps**
  
  Create new task definition revision:
  
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
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
  ],
  gql: `{
    queryawsEcsTaskDefinition {
      id
      arn
      accountId
       __typename
      containerDefinitions {
        mountPoints {
          readOnly
        }
      }
    }
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'medium',
  conditions: {  
    not: {
      path: '@.containerDefinitions',
      array_any: {
        path: '[*].mountPoints',
        array_any: {
          path: '[*].readOnly',
          equal: false,
        },
      },
    },
  },
}
