## [1.15.1-alpha.2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.1-alpha.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.1-alpha.2) (2023-05-17)


### Bug Fixes

* fix rule publication ([05da425](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/05da4255583ed119a06ca01710e194b62e2d2499))

## [1.15.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.1-alpha.1) (2023-05-17)


### Bug Fixes

* **checks:** Cannot read properties of undefined (reading 'direction') ([700a3de](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/700a3de4f5a7893aa9cba2238be485dc2254e7a6))

# [1.15.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.0) (2023-04-28)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* add validation for null references ([bb9811a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bb9811a977595260db3204165350821bebd30a50))
* **CG-1242:** fix aws cis 1.4.0, 1.16 rule ([0f6157f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/0f6157ff0a7cd0140ef7d0721f186f5f445338ff))
* **CG-1327:** fix AWS CIS 1.40 2.1.2 rule ([51a22e1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/51a22e1559eeedd566c138574fe75d1f02fa250c))
* **CG-1328:** fix the AWS CIS 1.4.0 2.1.5 rule ([2942785](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2942785d00b98351a24f4185eb7a3ace418a3c15))
* **CG-1329:** fix aws cis 1.4.0 rule 2.2.1 ([41457c4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41457c4916d521b0534bef6b3f9ba1ed8bb09883))
* **CG-1330:** AWS CIS 1.4.0 rule 3.8 fix ([d4f0421](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4f0421dc529652abe7cd89309664b63ef3ebe29))
* **CG-1331:** fix aws pci asg rule ([34f894f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/34f894f0f026c754914e5c063a4072c791a29637))
* **CG-1332:** fix aws pci ec2 check 1 ([71b45cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/71b45cfab75d11a2db6c9cff6e5968af76fb480d))
* **CG-1335:** AWS PCI IAM 1 rule fix ([f6c9f40](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f6c9f409beebf3240679cca678f5d0e18958f185))
* **CG-1336:** fix PCI IAM check 3 ([2188b34](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2188b3446200ef5646ac98eefaf73e5fd95615b2))
* changed wrong source property by destination on SG query ([700d370](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/700d3707b0cd4a5cc91e06d9dfb773d09529b113))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))
* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))
* **pnpm:** using semantic-release-pnpm ([41e9cca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41e9cca064a9f0e661f81f27c31f7d047df287de))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([a794f9e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a794f9ec37c076fde5d660a49e8b313bc79236ea))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([6fec472](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6fec472ecd10381f3b90f362f8c31519db9b0f53))
* rewritten rules to be scoped to the subscription level ([997aaad](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/997aaadafbb47a15cd492dced445c0f0537c7246))
* **test:** fix duplicate import ([2bac2fd](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2bac2fd43d3248bad8a408cfcd8ce4b5bba75d18))
* update .npmignore to include all rules in package ([3dd7a87](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3dd7a874ee4ff52ae8d6f948f39dcf8655eeda87))


### Features

* Add rules to readme file ([e0b2291](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e0b2291b96e674733755db78fec6e928a80de691))
* Added NIST rules from CG-1182 ([b961b2a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b961b2a13abf8f23c0b82651d531f393e1b76074))
* **CG-1151:** support gcp nist IAM default audit log config check ([b821ecf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b821ecfe243ce1df874374834b39193d685ad623))
* **CG-1164:** add Activity Log Retention ([ec03e27](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ec03e276159daa8a57da018071e32b73d6aa91ab))
* **CG-1164:** add azure pci sql server auditing enabled check ([a9e34a7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a9e34a717d8f864fa8c98a33ccb36a3420dd8098))
* **CG-1165:** add azure monitoring rule ([4383c3c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4383c3ca29a5a85a52a206590f71545ee09d713b))
* **CG-1165:** add azure pci monitor log profile rule ([a72f81c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a72f81c49c4a30704d5ad641de290d52114282d8))
* **CG-1165:** rule name update ([4ca8eb7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4ca8eb7d53f6e99a9655ff7bb86eb889ab027115))
* **CG-1165:** update README ([11e2604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/11e26043b301c0dfc7235552870d4f88b472a6a2))
* **CG-1168:** add azure networking 3 rule ([6d3925d](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6d3925dfbd6c06e717a3ce650b594a8e6baa0df0))
* **CG-1169:** add azure user-check-1 rule ([2f1ef53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2f1ef537624f30b644d8b4ca15881a052f3ee007))
* **CG-1173:** add azure WAF enabled check ([a6a8b31](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a6a8b31b40d4711e043ac2e717df2ee5491f1c5a))
* **CG-1174:** fix monitoring check 5 ([4b3c357](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4b3c357096cc50d729b542b4204fb7c8a2bcf88c))
* **CG-1174:** support azure pci monitoring rules ([3b86f5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3b86f5cd017409e11b5e4d5d1aa6867349f81a9b))
* **CG-1175:** add azure encryption transit rule check ([e6f01d4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6f01d4bcf02d5d7f243ad96fec4302e75a58e9b))
* **CG-1176:** add network access rules and policies version check rules ([d4e1604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4e16043affc4553d4fb56d05f908461ff439123))
* **CG-1176:** merge from alpha conflict resolved ([8be4624](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/8be4624d2479435dd774d73255ca5c2a26611466))
* **CG-1176:** README update ([bfde2ed](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bfde2edced9fab3210c9a69a740a1659b9208bd1))
* **CG-1263:** update azure network watcher cis and nist rule ([af8853e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/af8853e4f21338f1f6e80f9644550131372b89c6))
* **CG-1280:** add aws cis 1.5 iam rules ([9bac0ec](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9bac0ec8ceb27ca2f77a85f4d11154f311a75b12))
* **CG-1281:** add aws cis 1.5 logging rules ([1bf5c08](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/1bf5c08273a5ea41f842ce9d8be48802a50a1bcf))
* **CG-1282:** add support monitoring rules ([46c9483](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/46c94833fae665b9ab12482a247ff5a63d03fc42))
* **CG-1283:** add AWS CIS 1.5.0 4.16 rule ([fe66eac](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe66eacf5dce85893bdcd3d6e256800ba9a70858))
* **CG-1283:** partial rule ([2b5c662](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2b5c66256478a6206f420b01a4af780d32bc30be))
* **CG-1284:** add networking rule support ([b758b72](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b758b72735948f823b131b30b82be3794b1d2215))
* **CG-1285:** add aws cis 150 5.3 ([6528999](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/65289997ec7a51f07b3a4392db7d487206418828))
* **CG-1286:** add storage rules support ([0934441](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/09344413a18f1f6289e1cd02f8d594983b5dde46))
* **CG-1287:** add aws cis 2.3.2 support ([e6ee33f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6ee33fec483681e6539df01a3aa89359073e11b))
* **CG-1288:** add aws cis 233 support ([81359bf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/81359bf30d66f3d849f1c6b8b3b6cd9ab1356842))
* **CG-1289:** add aws cis 1.5.0 2.4.1 ([998bf70](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/998bf7013e8c3acbc8633ced5e449464a6ee3d26))
* **CG-1290:** create boilerplate for aws cis 1.5.0 ([9c1d6f3](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9c1d6f392a03b506424e74682caca85ff9188238))
* **CG-1291:** add gcp cis 130 boilerplate ([f7d6418](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f7d6418826ba53ca588a552ad5a7b58300bfe468))
* **CG-1292:** add GCP CIS 1.3 rules similar to 1.2 ([ff12a3f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ff12a3fed175cfeed414c4bf3d727ad65699230d))
* **CG-1293:** add GCP CIS 1.30 1.16 rule ([286ea82](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/286ea828eaa472848613bd977663fd56002d1f78))
* **CG-1293:** update the rule checker ([3e992cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3e992cf0d929c0e1e830e907e2ecc2a674cac77e))
* **CG-1294:** add GCP CIS 1.30 1.18 rule ([6cea799](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6cea799e50f7f0237648f578982010cbc3d05387))
* **CG-1294:** fix title ([751a65a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/751a65a830da19c7b2ae9af217df597b311e9131))
* **CG-1298:** add GCP CIS 1.30 2.13 ([cbe48df](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/cbe48dff0d0ea0769aa7c16aef9b81e9ddcf66d3))
* **CG-1298:** gql fix in the rule ([7799c95](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7799c955dce9385e8cce19d1a3f6cfd9bcec2dc0))
* **CG-1298:** update uniot test ([33e5b42](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/33e5b429edbb4f49230d893c019f5ff4b6c59d81))
* **CG-1299:** add GCP CIS 1.30 2.14 rule ([2baa517](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2baa5174dd36e98d6e71cd3c5f8064e850c069bf))
* **CG-1300:** add gcp cis 1.30 2.15 ([fe76508](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe76508cfb7cbc5ce90b6cc6d51949e55c9a3117))
* **CG-1302:** add gcp cis 1.30 3.10 ([9f0fa54](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9f0fa549a54fe9918746b006bb7ddbdf5e5b649a))
* **CG-1304:** add gcp cis 1.30 4.12 ([b718845](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b718845e0b66999852178afa53d31f6ba4e226d8))
* **CG-1306:** pushed wrong rule, fixed ([256cd5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/256cd5cb89e1356508f9542e53127177328d8410))
* **checks:** Support [AZURE NIST] Logging, Performance and Reliability, User and Role Management, and Using Updated Policies and Frameworks rules ([b810b0f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b810b0f679ed41e7aea6730a705feb7124e11dea))
* **ckecks:** add azure nist rule 3.7 and 6.x ([af7ae17](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/af7ae17c6e7f5a12204dfa9c6e68d05ffc86a25b))
* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))
* fixed and migrated rules from jq to js (rules-exclude branch) ([7c426ca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7c426ca709b68bc0af8bfad96e50e3bcf31eaca2))
* Update rules and sdk package version ([450b676](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/450b676836834634190c792e5a0e311dd41e5551))
* Update some rules and tests ([5ab30a4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/5ab30a4fa15885b23b586629afa222faaa7b84b3))

# [@cloudgraph/policy-pack-azure-cis-1.3.1-v1.15.0-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.0-alpha.1) (2022-12-14)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))
* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))
* rewritten rules to be scoped to the subscription level ([997aaad](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/997aaadafbb47a15cd492dced445c0f0537c7246))
* update .npmignore to include all rules in package ([3dd7a87](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3dd7a874ee4ff52ae8d6f948f39dcf8655eeda87))


### Features

* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))
* Update rules and sdk package version ([450b676](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/450b676836834634190c792e5a0e311dd41e5551))

# [@cloudgraph/policy-pack-azure-cis-1.3.1-v1.16.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.0) (2022-08-01)


### Bug Fixes

* rewritten rules to be scoped to the subscription level ([997aaad](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/997aaadafbb47a15cd492dced445c0f0537c7246))


### Features
* Update rules and sdk package version ([450b676](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/450b676836834634190c792e5a0e311dd41e5551))

# [@cloudgraph/policy-pack-azure-cis-1.3.1-v1.15.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.1) (2022-07-11)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))
* update .npmignore to include all rules in package ([3dd7a87](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3dd7a874ee4ff52ae8d6f948f39dcf8655eeda87))


### Features

* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))

# [@cloudgraph/policy-pack-azure-cis-1.3.1-v1.15.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.15.0) (2022-07-11)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))


### Features

* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))

# [@cloudgraph/policy-pack-azure-cis-1.3.1-v1.14.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.2...@cloudgraph/policy-pack-azure-cis-1.3.1@1.14.0) (2022-07-05)


## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.13.2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.2) (2022-05-26)


### Bug Fixes

* Azure CIS 1.3.1 rule 9.6 has the wrong title number ([e27efdb](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e27efdbb93c820bc39c7e09aae751da7dbdffc5f))

## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.13.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.1) (2022-05-02)


### Bug Fixes

* azure-cis-1.3.1-4.3.8 and pci-dss-3.2.1-lambda-check-1 rules ([5eca392](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/5eca392468b3d0457e7c16b44f367cd5f9cf2824))

## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.13.1-beta.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.1-beta.1) (2022-05-02)


### Bug Fixes

* azure-cis-1.3.1-4.3.8 and pci-dss-3.2.1-lambda-check-1 rules ([5eca392](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/5eca392468b3d0457e7c16b44f367cd5f9cf2824))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.13.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.12.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.13.0) (2022-03-31)


### Bug Fixes

* 5.3 title azure cis 1.3.1 ([9a64e22](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/9a64e228533666ea9be25f8960b2115d1e17d600))
* 5.3 title azure cis 1.3.1 ([e3f481b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e3f481bc19856752b823e92a32b51446c7ddd87d))
* check activityLogAlerts from resource group azure cis 1.3.1 ([7765532](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/7765532b12c64218f09e86324e29c65c97c4484c))
* index ([bc5def4](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bc5def458c89ed8ec35f57f751ddf8221b67677d))
* index ([8415a2b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8415a2b39fb77a1851ab25b62af191b3db32ab8d))
* resolve Azure CIS 1.3.1 test rebase conflict ([8257de8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8257de85521ba5083a4d445adf6eb4022f0d640f))


### Features

* Included 4.1.2, 4.3.1, 4.3.2, 5.2.7, 5.2.8, 5.2.9, 5.3 for azure cis 1.3.1 ([7b7cc46](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/7b7cc460e0541ae2cf9284cc2ff0613265867db1))
* Included 4.1.2, 4.3.1, 4.3.2, 5.2.7, 5.2.8, 5.2.9, 5.3 for azure cis 1.3.1 ([b4cdc13](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b4cdc1308b53ceae257a0fe8ae89e0bb7e7dc6f8))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.12.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.11.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.12.0) (2022-03-30)


### Bug Fixes

* index ([9381561](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/93815616b2a662acaca4e2444925be67283345d5))


### Features

* Included 4.1.1, 4.1.3, 4.3.3, 4.3.4 rules for azure cis 1.3.1 ([5291aee](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/5291aeeabe4632aba41cc7f046eece2fb2270b93))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.11.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.10.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.11.0) (2022-03-30)


### Features

* **checks:** Included 5.1.x rules for azure cis 1.3.1 ([be84ef6](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/be84ef66375ed6c31e1eeb7cf1c987283ae85798))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.10.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.9.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.10.0) (2022-03-30)


### Bug Fixes

* 5.2.1, 5.2.2 conditions azure cis 1.3.1 ([bc0623b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bc0623bd9cbcd0f10fb161fdc772a7814a54b9be))
* 5.2.x resource group level array_any for activityLogAlerts ([bb40e16](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bb40e16ab916e3801bf4dee15a9bedd8161e6fa2))
* condition equal for azure cis 1.3.1 ([b8116a0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b8116a0f4a24fc2b4c18894dc7a1e95d21a63477))
* Fixed unit tests for Azure CIS 1.3.1 rule 9.10 ([27fcd91](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/27fcd910647d3a509d86dcad03cddf7440b152e2))


### Features

* Included 5.2.1-5.2.6 for azure cis 1.3.1 ([4bfb87a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/4bfb87a55825812d29720d056c00c2c202801384))
* Split composite rules for better granularity ([6f260ba](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/6f260ba7b55848ad275d14a659de38d853b2877c))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.9.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.8.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.9.0) (2022-03-18)


### Features

* Included 4.3.5, 4.3.6, 4.3.7 and 4.3.8 rules for azure cis 1.3.1 ([9661be7](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/9661be7a0366e7c9aff1b89b569874ddb12dc0f1))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.8.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.7.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.8.0) (2022-03-15)


### Bug Fixes

* azure cis 1.3.1: 4.2.3 ([d85e9ba](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/d85e9ba8bc2bbd5e4082f938e5abc488709f6baf))


### Features

* Included 4.2.1-4.2.5 rules for azure cis 1.3.1 ([3d93785](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/3d93785731e7dd76aaf55a34bcb8f2b6213c97f8))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.7.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.6.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.7.0) (2022-03-11)


### Features

* Included 4.4 and 4.5 rules for azure cis 1.3.1 ([cc505bf](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/cc505bf67f0add38eab55025f180b4d5dff17ef0))
* Included 8.1, 8.2, 8.3, 8.4, 8.5 rules for azure cis 1.3.1 ([0ac4ac8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0ac4ac87e383335f22c923f5aa6b34c0a6a0903a))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.6.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.5.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.6.0) (2022-03-11)


### Features

* Included 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7 rules for azure cis 1.3.1 ([50469b2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/50469b2c5ea2fc702b84eddf5445fca37ef0089c))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.5.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.4.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.5.0) (2022-03-10)


### Features

* Included 6.1, 6.2, 6.3, 6.4, 6.5, 6.6 rules for azure cis 1.3.1 ([6fa7cef](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/6fa7cef77b8ee4c326408d31c215d3c0f0e695f9))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.4.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.2...@cloudgraph/policy-pack-azure-cis-1.3.1@1.4.0) (2022-03-08)


### Bug Fixes

* severity/condition for Azure CIS 2.11-2.13 ([a5a279c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/a5a279cba52d65a346e14b11a6a4a82e364a71eb))


### Features

* Included 2.9-2.14 for azure cis 1.3.1 ([e2a3f4a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e2a3f4af3108e368b60ce4b23deba9f850cf18ff))

## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.3.2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.2) (2022-03-04)


### Bug Fixes

* Fixed README for azure CIS 1.3.1 ([00c82e9](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/00c82e9e937189e9a8fdf042de2f815d7c06bf68))

## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.3.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.1) (2022-03-04)


### Bug Fixes

* azure cis 9.x rules unit tests ([54ccf4b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/54ccf4b25e4dc3d2edc80744317039592b0f59f6))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.3.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.2.1...@cloudgraph/policy-pack-azure-cis-1.3.1@1.3.0) (2022-03-04)


### Features

* Included 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 9.11 rules for azure cis 1.3.1 ([eaed8bc](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/eaed8bc92e5a02bb2982b266eb276ab32b7cec34))

## @cloudgraph/policy-pack-azure-cis-1.3.1 [1.2.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.2.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.2.1) (2022-03-01)


### Bug Fixes

* Fixed tests for azure cis 1.2.0 3.x ([9317878](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/9317878457cb240ecbae8f68036306f4b18fdd31))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.2.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.1.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.2.0) (2022-02-25)


### Features

* Included 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11 rules for azure cis 1.3.1 ([25c02d2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/25c02d296c4df21bfd7ef1dfdf2ab8bf789ee715))

# @cloudgraph/policy-pack-azure-cis-1.3.1 [1.1.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-azure-cis-1.3.1@1.0.0...@cloudgraph/policy-pack-azure-cis-1.3.1@1.1.0) (2022-02-22)


### Features

* Included 1.14, 1.15, 1.16, 1.17, 1.18, 1.19 rules for azure cis 1.3.1 ([81584ac](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/81584ac0f9ffd4be3856367ea627b923ee3efef9))
* Included 1.22 rule for azure cis 1.3.1 ([ba7aec1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ba7aec18ead1e2a76c092e50f3aec8de2e8aa4fa))
* Included 1.3, 1.20, 1.21, 1.23 ([b911b13](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b911b13a8afe0323e0c6725906ac6b4c8dc1753d))
* Included 2.1, 1.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8 rules for azure cis 1.3.1 ([6d4e17f](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/6d4e17f7a24c08aa791f1053da9cc23e8d512caa))

# @cloudgraph/policy-pack-azure-cis-1.3.1 1.0.0 (2022-02-15)


### Features

* Included 1.1, 1.2, 1.4, 1.5, 1.6, 1.7 rules for azure cis 1.3.1 ([c4eee61](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/c4eee61b4df70d9da78a82e11bf4bb87a48ec55e))
