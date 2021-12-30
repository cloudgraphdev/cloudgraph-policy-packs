#!/usr/bin/env node

if( process.argv.length != 3  ) {
  console.error("Must pass a sigle tag name");
  process.exit(1)
}

const tagArr = process.argv[2].split("@").slice(0,2)
const workspace = tagArr.join("@")
console.log(workspace)
