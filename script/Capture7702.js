// script/Capture7702.js
import { createPublicClient, createWalletClient, http, encodeFunctionData, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

// ---- ENV / CONSTANTS ----
const ETH_RPC_URL = process.env.ETH_RPC_URL;                       // e.g. https://sepolia.infura.io/v3/...
const PRIVATE_KEY  = process.env.PRIVATE_KEY;                      // 0x...
const TARGET = getAddress(process.env.TARGET ?? '0x6b27209c24Ad55819719288fa51aDa66732633f7');
const IMPL   = getAddress(process.env.IMPL   ?? '0xA6a223FdDDe89Fa7f587C37200dd65664f061B74');

// ---- ABIs ----
const challengeAbi = [{ name:'flag', type:'function', stateMutability:'view', inputs:[], outputs:[{type:'address'}] }];
const implAbi = [{ name:'capture', type:'function', stateMutability:'payable', inputs:[{name:'target', type:'address'}], outputs:[] }];

// ---- Clients ----
const pub = createPublicClient({ chain: sepolia, transport: http(ETH_RPC_URL) });
const account = privateKeyToAccount(PRIVATE_KEY);
const wallet = createWalletClient({ account, chain: sepolia, transport: http(ETH_RPC_URL) });

(async () => {
  console.log('EOA   :', account.address);
  console.log('Target:', TARGET);
  console.log('Impl  :', IMPL);

  const before = await pub.readContract({ address: TARGET, abi: challengeAbi, functionName: 'flag' });
  console.log('flag() BEFORE =', before);

  // 1) EIP-7702 authorization: designate IMPL onto the EOA (self-executed)
  const authorization = await wallet.signAuthorization({
    account,            // signer is the EOA that will also execute
    contractAddress: IMPL,
    executor: 'self',   // IMPORTANT when the same EOA sends the tx
  });

  // 2) Send 0x04 tx to your EOA, calling IMPL.capture(TARGET)
  const hash = await wallet.sendTransaction({
    to: account.address,                           // EOA runs IMPL bytecode for this tx
    authorizationList: [authorization],            // EIP-7702
    data: encodeFunctionData({ abi: implAbi, functionName: 'capture', args: [TARGET] }),
  });
  console.log('sent tx:', hash);

  const receipt = await pub.waitForTransactionReceipt({ hash });
  console.log('mined in block:', receipt.blockNumber);

  const after = await pub.readContract({ address: TARGET, abi: challengeAbi, functionName: 'flag' });
  console.log('flag() AFTER  =', after);
})();

