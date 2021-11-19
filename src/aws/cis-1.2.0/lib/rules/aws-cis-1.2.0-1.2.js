"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'aws-cis-1.2.0-1.2',
    description: 'AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password (Scored)',
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
        path: '@.mfaDevices',
        isEmpty: true,
    },
};
