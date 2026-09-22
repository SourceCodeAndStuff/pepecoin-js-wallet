/**
 * Wallet service tests for ownership, encrypted keys, idempotent withdrawals, and spend safety.
 * Balances use synthetic coins; no real transactions are broadcast.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rename } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { WalletVault } from '../lib/wallet-vault.js';
import { WalletService } from '../lib/wallet-service.js';
import { createWallet, walletFromPrivateKey, importWif, wif, destinationScript, base58Check, passwordKey, passwordHash, encryptPrivateKey } from '../lib/wallet.js';
import { buildPayment, signMessage, verifyMessage, ribbit } from '../lib/wallet-signing.js';
import { parseBlock } from '../lib/pepenet-wire.js';
import { verifyP2pkhInput } from './helpers/p2pkh.js';

/**
 * Create an isolated vault, synthetic funded index, and counted fake relay.
 * @param {import("node:test").TestContext} t - Registers fixture cleanup.
 * @returns {Promise<object>} Service dependencies and synthetic wallet.
 */
async function fixture(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(),'pepe-application-test-'));
  const vault = new WalletVault(dir); t.after(()=>{if(vault.db.open)vault.close();});
  const data = { height:1000, utxos:[], transactions:[], legacyPending:[] };
  const index = { watchIdentity:async()=>{}, walletSnapshot:async ids=>({...data,utxos:data.utxos.filter(u=>ids.includes(u.identity)),transactions:data.transactions.filter(u=>ids.includes(u.identity))}) };
  const status = { state:'synced',height:1000,targetHeight:1000,lastSyncedAt:new Date().toISOString() };
  let broadcasts=0;
  const service = new WalletService({vault,index,status,broadcast:async()=>{broadcasts++;}});
  const wallet = await service.create('owner','account-1','Account One');
  data.utxos.push({identity:wallet.addresses[0].identity,txid:'11'.repeat(32),vout:0,valueKoinu:'1000000000',height:1,coinbase:0});
  return {dir,vault,index,status,service,data,wallet,broadcasts:()=>broadcasts};
}
/**
 * Build a one-PEPE test payment.
 * @param {string} address - Fixture destination.
 * @returns {object} Recipient input for quoting or sending.
 */
const body = address => ({recipients:[{address,amount:'1.00000000'}]});

test('ribbits are integer atomic amounts and fee errors use the correct unit', () => {
  assert.equal(ribbit('0.00000001'), 1n);
  assert.equal(ribbit('1'), 100000000n);
  assert.throws(() => buildPayment({ recipients: [{}], feeRate: '999' }), /1000 ribbits per byte/);
});

test('native key/WIF and compact message signatures round-trip compressed and uncompressed',()=>{
  for(const compressed of [true,false]) {
    const wallet=walletFromPrivateKey(createWallet().privateKey,compressed);
    const imported=importWif(wif(wallet.privateKey,compressed));
    assert.equal(imported.address,wallet.address);assert.equal(imported.compressed,compressed);
    const signature=signMessage(wallet.privateKey,'Application withdrawal authorization',compressed);
    assert.ok(verifyMessage(wallet.address,'Application withdrawal authorization',signature));
    assert.equal(verifyMessage(wallet.address,'Different message',signature),false);
    assert.equal(verifyMessage(createWallet().address,'Application withdrawal authorization',signature),false);
  }
  assert.throws(()=>importWif('not a private key'));assert.throws(()=>ribbit(1));assert.throws(()=>ribbit('1e-8'));assert.throws(()=>ribbit('0.000000001'));
});
test('multi-address payments produce verifiable native signatures and P2SH destinations',()=>{
  const a=createWallet(),b=walletFromPrivateKey(createWallet().privateKey,false),destination=base58Check(Buffer.concat([Buffer.from([22]),randomBytes(20)]));
  const wallets=new Map([a,b].map(w=>[w.identity.toString('hex'),w]));
  const inputs=[a,b].map((w,i)=>({identity:w.identity.toString('hex'),txid:String(i+1).repeat(64),vout:i,valueKoinu:'100000000'}));
  const payment=buildPayment({utxos:inputs,recipients:[{address:destination,amount:'1.5'}],changeAddress:a.address,keyFor:id=>wallets.get(id)});
  const tx=parseBlock(Buffer.concat([Buffer.alloc(80),Buffer.from([1]),payment.raw])).transactions[0];
  for(let i=0;i<2;i++) assert.equal(verifyP2pkhInput(tx,i).identity.toString('hex'),inputs[i].identity);
  assert.deepEqual(tx.outputs[0].scriptPubKey,destinationScript(destination));
  assert.equal(200000000n-tx.outputs.reduce((n,o)=>n+o.value,0n),BigInt(payment.feeKoinu));
  assert.ok(BigInt(payment.feeKoinu)>=BigInt(payment.raw.length)*1000n);
});
test('account creation is idempotent, private keys are encrypted, and tenants are isolated',async t=>{
  const f=await fixture(t),again=await f.service.create('owner','account-1','Changed label');
  assert.equal(again.id,f.wallet.id);assert.equal(again.addresses[0].address,f.wallet.addresses[0].address);
  assert.throws(()=>f.vault.get('someone-else',f.wallet.id),/not found/);
  assert.throws(()=>f.vault.addAddress(f.vault.create('other','p','P').id,walletFromPrivateKey(f.vault.signingKey(f.wallet.id,f.wallet.addresses[0].identity).privateKey)),/another wallet/);
  const row=f.vault.db.prepare('SELECT secret FROM addresses WHERE walletId=?').get(f.wallet.id);
  assert.notEqual(row.secret,f.vault.signingKey(f.wallet.id,f.wallet.addresses[0].identity).privateKey.toString('hex'));
  assert.ok(!JSON.stringify(f.vault.list('owner')).includes(row.secret));
});
test('duplicate and concurrent withdrawal requests cannot send a second payment',async t=>{
  const f=await fixture(t),input=body(createWallet().address);
  const [a,b]=await Promise.all([f.service.send('owner',f.wallet.id,input,'order-1'),f.service.send('owner',f.wallet.id,input,'order-1')]);
  assert.equal(a.txid,b.txid);assert.equal(f.broadcasts(),1);assert.equal(f.vault.outgoing(f.wallet.id).length,1);
  await assert.rejects(f.service.send('owner',f.wallet.id,body(createWallet().address),'order-1'),/different withdrawal/);
  await assert.rejects(f.service.send('owner',f.wallet.id,input,'order-2'),/spendable coins/);
  assert.equal((await f.service.snapshot('owner',f.wallet.id)).available,'0.00000000');
});
test('uncertain relay preserves inputs and exact transaction across vault restart',async t=>{
  const f=await fixture(t);f.service.broadcast=async()=>{throw new Error('timeout');};
  const input=body(createWallet().address),p=await f.service.send('owner',f.wallet.id,input,'retryable');
  assert.equal(p.state,'unverified');const raw=f.vault.db.prepare('SELECT raw FROM outgoing').get().raw;
  f.vault.close();const reopened=new WalletVault(f.dir);t.after(()=>reopened.close());
  const service=new WalletService({vault:reopened,index:f.index,status:f.status,broadcast:async bytes=>{assert.equal(bytes.toString('hex'),raw);}});
  assert.equal((await service.send('owner',f.wallet.id,input,'retryable')).txid,p.txid);
  assert.equal((await service.rebroadcast('owner',f.wallet.id,p.id)).state,'relayed');
  assert.equal(reopened.blocked(f.wallet.id).size,1);
});
test('stale sync, immature coinbase, locked coins and imported keys cannot be spent',async t=>{
  const f=await fixture(t),input=body(createWallet().address);
  f.status.lastSyncedAt=new Date(Date.now()-180000).toISOString();await assert.rejects(f.service.quote('owner',f.wallet.id,input),/up to date/);
  f.status.lastSyncedAt=new Date().toISOString();f.data.utxos[0].coinbase=1;f.data.utxos[0].height=990;
  assert.equal((await f.service.snapshot('owner',f.wallet.id)).available,'0.00000000');
  f.data.utxos[0].height=1;f.vault.db.prepare('INSERT INTO coin_locks VALUES (?,?)').run(f.wallet.id,'11'.repeat(32)+':0');
  assert.equal((await f.service.snapshot('owner',f.wallet.id)).available,'0.00000000');
  f.vault.db.prepare('DELETE FROM coin_locks').run();f.vault.addAddress(f.wallet.id,createWallet(),'Import',true);
  await assert.rejects(f.service.quote('owner',f.wallet.id,input),/rescan/);
});
test('encrypted backups restore keys and pending reservations without API secrets',async t=>{
  const f=await fixture(t);await f.service.send('owner',f.wallet.id,body(createWallet().address),'backup-order');
  const backup=f.vault.backup('owner','a long backup password');
  assert.ok(!JSON.stringify(backup).includes(f.wallet.addresses[0].address));
  const dir=await mkdtemp(path.join(os.tmpdir(),'pepe-restore-test-')),v=new WalletVault(dir);t.after(()=>v.close());
  assert.throws(()=>v.restore('new-owner',backup,'a wrong backup password'));
  assert.equal(v.list('new-owner').length,0);
  v.restore('new-owner',backup,'a long backup password');
  const restored=v.list('new-owner')[0];assert.equal(restored.addresses[0].address,f.wallet.addresses[0].address);assert.equal(restored.addresses[0].needsRescan,1);
  assert.equal(v.outgoing(restored.id).length,1);assert.equal(v.blocked(restored.id).size,1);
});
test('missing master key fails closed rather than silently creating a replacement',async t=>{
  const f=await fixture(t);f.vault.close();await rename(path.join(f.dir,'wallet.key'),path.join(f.dir,'wallet.key.saved'));
  assert.throws(()=>new WalletVault(f.dir),/missing/);
  assert.equal((await readFile(path.join(f.dir,'wallet.key.saved'))).length,32);
});
