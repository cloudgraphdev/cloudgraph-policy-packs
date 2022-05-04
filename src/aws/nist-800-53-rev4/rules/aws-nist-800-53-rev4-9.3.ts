export default {
  id: 'aws-nist-800-53-rev4-9.3',  
  title: 'AWS NIST 9.3 ECS task definitions should not add Linux capabilities beyond defaults and should drop ‘NET_RAW’',
  
  description: `Docker containers are started with a default set of Linux capabilities. Adding capabilities allows users to grant some superuser permissions to a process without running that process as root. This rule enforces two valid states either drop ‘NET_RAW’ and do not add any other capabilities, or drop ‘ALL’ and only add back the capabilities that you need. We recommend that this rule be waived on a per-task basis.
  
  Linux capabilities should be modified by specifying **KernelCapabilities** for each **ContainerDefinition** within the task definition. For more information about linux capabilities in the context of ECS, see [KernelCapabilities](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_KernelCapabilities.html) in the ECS API reference.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory limits, or port mappings), select the container, make the changes, and then choose Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see Updating a service.
  
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
        linuxParameters {
          capabilities {
            drop
          }
        }
      }
    }
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'high',
  conditions: {  
    path: '@.containerDefinitions',
    array_all: {
      or: [
        {
          path: '[*].linuxParameters.capabilities.drop',
          contains: 'ALL',
        },
        {
          and: [
            {
              path: '[*].linuxParameters.capabilities.drop',
              contains: 'NET_RAW',
            },
            {
              path: '[*].linuxParameters.capabilities.add',
              isEmpty: true
            },
          ],
        },
      ],
    },
  },
}
