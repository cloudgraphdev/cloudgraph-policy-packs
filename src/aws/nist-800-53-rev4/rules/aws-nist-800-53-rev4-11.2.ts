export default {
  id: 'aws-nist-800-53-rev4-11.2',  
  title: 'ECS task definitions should set CPU limit for containers',
  
  description: 'Unless specified, containers get access to all the CPU and memory capacity available' +
  'on that host. Specifying CPU for ECS task definitions ensures that high priority containers are able' +
  'to claim the CPU runtime they require.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**

  - Navigate to ECS.
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory limits, or port mappings), select the container, make the changes, and then choose Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see Updating a service.

  **AWS CLI**   
  - Create new task definition revision:
  > aws ecs register-task-definition <br>
  > --family \<value> <br>
  > [--task-role-arn \<value>] <br>
  > [--execution-role-arn \<value>] <br>
  > [--network-mode \<value>] <br>
  > --container-definitions \<value> <br>
  > [--volumes \<value>] <br>
  > [--placement-constraints \<value>] <br>
  > [--requires-compatibilities \<value>] <br>
  > [--cpu \<value>] <br>
  > [--memory \<value>] <br>
  > [--tags \<value>] <br>
  > [--pid-mode \<value>] <br>
  > [--ipc-mode \<value>] <br>
  > [--proxy-configuration \<value>] <br>
  > [--inference-accelerators \<value>] <br>
  > [--cli-input-json | --cli-input-yaml] <br>
  > [--generate-cli-skeleton \<value>]

  - Update the service to use the new task definition:
  > aws ecs update-service
  > [--cluster \<value>]
  > --service \<value>
  > [--desired-count \<value>]
  > [--task-definition \<value>]
  > [--capacity-provider-strategy \<value>]
  > [--deployment-configuration \<value>]
  > [--network-configuration \<value>]
  > [--placement-constraints \<value>]
  > [--placement-strategy \<value>]
  > [--platform-version \<value>]
  > [--force-new-deployment | --no-force-new-deployment]
  > [--health-check-grace-period-seconds \<value>]
  > [--cli-input-json | --cli-input-yaml]
  > [--generate-cli-skeleton \<value>]`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
  ],
  gql: `{
    queryawsEcsTask {
      id
      arn
      accountId
      __typename
      cpu
      launchType
    }    
  }`,
  resource: 'queryawsEcsTask[*]',
  severity: 'medium',
  conditions: {
    path: '@.cpu',
    in: ["0", "256", "512"]
  },
}