const hre = require("hardhat");

async function main() {
  const verifier = await hre.ethers.getContractFactory("Verifier");
  const vrfr = await verifier.deploy();

  await vrfr.deployed();

  console.log("verifier deployed to:", vrfr.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
