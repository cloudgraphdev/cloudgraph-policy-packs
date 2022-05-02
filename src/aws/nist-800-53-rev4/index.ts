import PolicyPacksRules from './rules'

export default {
  provider: 'aws',
  entity: 'NIST',
  rules: PolicyPacksRules,
  extraFields: ['arn', 'accountId']
}
