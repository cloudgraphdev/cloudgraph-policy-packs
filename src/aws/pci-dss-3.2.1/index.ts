import PolicyPacksRules from './rules'

export default {
  provider: 'aws',
  entity: 'PCI',
  rules: PolicyPacksRules,
  extraFields: ['arn', 'accountId'],
}
