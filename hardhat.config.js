require("@nomiclabs/hardhat-waffle");

require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.12",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },

  networks: {
    ganache: {
      url: `http://127.0.0.1:7545`,
      accounts: [`${process.env.GANACHE_PRIVATE_KEY}`]
    }
  },
};
