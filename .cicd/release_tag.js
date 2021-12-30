#!/usr/bin/env node

if( process.argv.length != 3  ) {
  console.error("Must pass a sigle tag name");
  process.exit(1)
}

const alphaRegex = /(.)+\-alpha(.)+/
const betaRegex = /(.)+\-beta(.)+/

const gitTag = process.argv[2]

let releaseTag = null
switch(true) {
  case (alphaRegex.test(gitTag)):
    releaseTag = 'alpha'
    break
  case (betaRegex.test(gitTag)):
    releaseTag = 'beta'
    break
  default:
    releaseTag = 'latest'
}

console.log(releaseTag)
