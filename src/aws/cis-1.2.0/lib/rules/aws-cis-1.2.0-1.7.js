"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'aws-cis-1.2.0-1.7',
    description: 'AWS CIS 1.7  Ensure IAM password policy requires at least one symbol',
    gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireSymbols
    }
  }`,
    resource: 'queryawsIamPasswordPolicy[*]',
    conditions: {
        path: '@.requireSymbols',
        equal: false,
    },
};
