"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'aws-cis-1.2.0-1.11',
    description: 'AWS CIS 1.11 Ensure IAM password policy expires passwords within 90 days or less',
    gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      maxPasswordAge
    }
  }`,
    resource: 'queryawsIamPasswordPolicy[*]',
    conditions: {
        path: '@.maxPasswordAge',
        greaterThan: 90,
    },
};
