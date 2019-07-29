const md5 = require('md5');
const sha1 = require('sha1');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const scrypt = require('scrypt');


const pwd = {
  LOW: "helloworld",
  MED: "HelloWorld",
  STR: "Hello World !",
};

const hashes = {
  low: [],
  medium: [],
  strong: [],
};

const decrypt = (ashes) => {
  console.log(ashes);
};

const genHashes = async () => {
  console.time('Generating MD5 hashes');
  hashes.low.push({algorithm: "MD5", hash: md5(pwd.LOW)});
  hashes.medium.push({algorithm: "MD5", hash: md5(pwd.MED)});
  hashes.strong.push({algorithm: "MD5", hash: md5(pwd.STR)});
  console.timeEnd('Generating MD5 hashes');

  console.time('Generating SHA1 hashes');
  hashes.low.push({algorithm: "SHA1", hash: sha1(pwd.LOW)});
  hashes.medium.push({algorithm: "SHA1", hash: sha1(pwd.MED)});
  hashes.strong.push({algorithm: "SHA1", hash: sha1(pwd.STR)});
  console.timeEnd('Generating SHA1 hashes');

  console.time('Generating bcrypt hashes (Blowfish)');
  hashes.low.push({algorithm: "bcrypt", hash: bcrypt.hashSync(pwd.LOW, 8)});
  hashes.medium.push({algorithm: "bcrypt", hash: bcrypt.hashSync(pwd.MED, 8)});
  hashes.strong.push({algorithm: "bcrypt", hash: bcrypt.hashSync(pwd.STR, 8)});
  console.timeEnd('Generating bcrypt hashes (Blowfish)');

  console.time('Generating scrypt hashes');
  hashes.low.push({algorithm: "scrypt", hash: scrypt.hashSync(pwd.LOW, {"N":1024,"r":8,"p":16}, 64, "").toString("hex")});
  hashes.medium.push({algorithm: "scrypt", hash: scrypt.hashSync(pwd.MED, {"N":1024,"r":8,"p":16}, 64, "").toString("hex")});
  hashes.strong.push({algorithm: "scrypt", hash: scrypt.hashSync(pwd.STR, {"N":1024,"r":8,"p":16}, 64, "").toString("hex")});
  console.timeEnd('Generating scrypt hashes');

  console.time('Generating Argon2 hashes');
  hashes.low.push({algorithm: "argon2", hash: await argon2.hash(pwd.LOW)});
  hashes.medium.push({algorithm: "argon2", hash: await argon2.hash(pwd.MED)});
  hashes.strong.push({algorithm: "argon2", hash: await argon2.hash(pwd.STR)});
  console.timeEnd('Generating Argon2 hashes');

  return hashes;
};

const init = async () => {
  const hashes = await genHashes();
  decrypt(hashes);
};

init();
