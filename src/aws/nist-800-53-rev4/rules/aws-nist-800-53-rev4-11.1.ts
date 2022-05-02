export default {
  id: 'aws-nist-800-53-rev4-11.1',  
  title: 'ECS task definitions should limit memory usage for containers',
  
  description: `'Limiting memory usage for your ECS tasks allows you to avoid running out of memory because ECS stops placing tasks on the instance, and Docker kills any containers that try to go over the hard limit. Having no limit on memory usage can lead to issues where one container can easily make the whole system unstable and as a result unusable.'`,
  
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
  > [--task-role-arn \<value>]  <br>
  > [--execution-role-arn \<value>]  <br>
  > [--network-mode \<value>] <br>
  > --container-definitions \<value>  <br>
  > [--volumes \<value>]  <br>
  > [--placement-constraints \<value>]  <br>
  > [--requires-compatibilities \<value>]  <br>
  > [--cpu \<value>]  <br>
  > [--memory \<value>] <br>
  > [--tags \<value>] <br>
  > [--pid-mode \<value>] <br>
  > [--ipc-mode \<value>] <br>
  > [--proxy-configuration \<value>] <br>
  > [--inference-accelerators \<value>] <br>
  > [--cli-input-json | --cli-input-yaml] <br>
  > [--generate-cli-skeleton \<value>] <br>

- Update the service to use the new task definition:
  > aws ecs update-service <br>
  > [--cluster \<value>] <br>
  > --service \<value> <br>
  > [--desired-count \<value>] <br>
  > [--task-definition \<value>] <br>
  > [--capacity-provider-strategy \<value>] <br>
  > [--deployment-configuration \<value>] <br>
  > [--network-configuration \<value>] <br>
  > [--placement-constraints \<value>] <br>
  > [--placement-strategy \<value>] <br>
  > [--platform-version \<value>] <br>
  > [--force-new-deployment | --no-force-new-deployment] <br>
  > [--health-check-grace-period-seconds \<value>] <br>
  > [--cli-input-json | --cli-input-yaml] <br>
  > [--generate-cli-skeleton \<value>] <br>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
      'https://aws.amazon.com/blogs/containers/how-amazon-ecs-manages-cpu-and-memory-resources/',
  ],
  gql: `{
    queryawsEcsTaskDefinition {
      id
      arn
      accountId
      __typename
      memory
    }    
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'medium',
  conditions: {
    path: '@.memory',
    in: ["0", "256", "512"]
  },
}