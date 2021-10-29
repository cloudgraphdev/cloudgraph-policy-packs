export default {
  provider: 'aws',
  rules: [
    {
      id: 'r1',
      description: 'Security Group Opens All Ports to All',
      rationale: 'this is not good',
      // minCount: 0,
      // this query is not the best for this rule, but I'm playing
      // ie. there can be several ec2 inst with the same sec-group
      gql: `{
      queryawsEc2 {
        id
        arn
        securityGroups {
          id
          __typename # we could try to auto-inject this one
          inboundRules {
            source
            portRange
            protocol
          }
        }
      }
      }`,
      // the resource that will have the finding attached
      resource: 'queryawsEc2[*].securityGroups[*]',
      conditions: {
        path: '@.inboundRules',
        array_any: {
          and: [
            {
              path: '[*].source',
              in: ['0.0.0.0/0', '::/0', '68.250.115.158/32'],
            },

            { path: '[*].portRange', in: ['all', '0-65535'] },
          ],
        },
      },
      // check: (data: any): boolean => { // return false
      //   const secGroup = data.queryawsEc2['@'].securityGroups['@']; // curr resource
      //   return secGroup.inboundRules.some((ib: any) =>
      //     (ib.source === '0.0.0.0/0' || ib.source === '::/0') &&
      //     (ib.portRange === 'all' || ib.portRange === '0-65535'))
      // }
    },
    {
      id: 'r2',
      description:
        'AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled',
      gql: `{
       queryawsIamUser {
          id
          __typename
          passwordLastUsed
          accessKeyData {
            accessKeyId
            lastUsedDate
          }
        }
      }`,
      resource: 'queryawsIamUser[*]',
      conditions: {
        or: [
          {
            value: { daysAgo: {}, path: '@.passwordLastUsed' },
            greaterThan: 90,
          },
          {
            path: '@.accessKeyData',
            array_any: {
              value: { daysAgo: {}, path: '[*].lastUsedDate' },
              greaterThan: 90,
            },
          },
        ],
      },
    },
    {
      id: 'r3',
      description:
        'AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password (Scored)',
      gql: `{
        queryawsIamUser {
          id
          __typename
          passwordLastUsed
          mfaDevices {
            serialNumber
          }
        }
      }`,
      resource: 'queryawsIamUser[*]',
      conditions: {
        and: [
          { notEqual: '', path: '@.passwordLastUsed' },
          {
            path: '@.mfaDevices',
            array_all: { path: '[*]', greaterThan: 0 },
          },
        ],
      },
    },
    {
      id: 'r4',
      description:
        'AWS CIS 1.4 Ensure access keys are rotated every 90 days or less',
      gql: `{
        queryawsIamUser {
          id
           __typename
          accessKeyData {
            status
            lastUsedDate
          }
        }
      }`,
      resource: 'queryawsIamUser[*]',
      conditions: {
        and: [
          {
            path: '@.accessKeyData',
            array_any: {
              value: { daysAgo: {}, path: '[*].lastUsedDate' },
              greaterThan: 90,
            },
          },
          {
            path: '@.accessKeyData',
            array_any: { equal: 'Active', path: '[*].status' },
          },
        ],
      },
    },
    {
      id: 'r5',
      description:
        'AWS CIS 1.5  Ensure IAM password policy requires at least one uppercase letter',
      gql: `{
        queryawsIamPasswordPolicy {
          id
          __typename
          requireUppercaseCharacters
        }
      }`,
      resource: 'queryawsIamPasswordPolicy[*]',
      conditions: {
        path: '@.requireUppercaseCharacters',
        equal: true,
      },
    },
    {
      id: 'r6',
      description:
        'AWS CIS 1.6  Ensure IAM password policy requires at least one lowercase letter',
      gql: `{
        queryawsIamPasswordPolicy {
          id
          __typename
          requireLowercaseCharacters
        }
      }`,
      resource: 'queryawsIamPasswordPolicy[*]',
      conditions: {
        path: '@.requireLowercaseCharacters',
        equal: true,
      },
    },
  ],
}
