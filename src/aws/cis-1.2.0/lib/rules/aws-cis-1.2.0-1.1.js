"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'aws-cis-1.2.0-1.1',
    description: "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days (Scored)",
    gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      passwordLastUsed
    }
  }`,
    resource: 'queryawsIamUser[*]',
    conditions: {
        value: { daysAgo: {}, path: '@.passwordLastUsed' },
        greaterThan: 30,
    },
};
