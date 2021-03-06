import CloudGraph, { Engine, Result, Rule } from '@cloudgraph/sdk'
import DgraphDataProcessor from '@cloudgraph/sdk/dist/src/rules-engine/data-processors/dgraph-data-processor'

export const initRuleEngine = (
  providerName: string,
  entityName: string
): Engine =>
new CloudGraph.RulesEngine(new DgraphDataProcessor({ providerName, entityName}))

export const testRule = async (
  rulesEngine: Engine,
  data: any,
  rule: Rule,
  expectedResult: Result
): Promise<void> => {
  // Act
  const [processedRule] = await rulesEngine.processRule(rule as Rule, {
    ...data,
  })
  // Asserts
  expect(processedRule.result).toBe(expectedResult)
}