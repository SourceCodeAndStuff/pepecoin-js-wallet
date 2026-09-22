/**
 * Deterministic peer synchronization tests covering request windows, linked headers, and cancellation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PepecoinSync } from '../lib/pepenet-sync.js';
import { hash256d } from '../lib/pepenet-wire.js';
import { varInt } from '../lib/pepenet-p2p.js';

/**
 * Accept synthetic zero-work fixtures so these tests exercise paging and ordering only.
 * Mainnet header and body validation is covered by the tests at the end of this file.
 */
const trusting = { validateHeaders: (headers, context) => ({ height: context.height + headers.length, recent: [] }), checkBlock() {} };

/**
 * Minimal event-driven peer recording outgoing requests for deterministic assertions.
 */
class Peer extends EventEmitter {
  /**
   * @param {boolean} [ready=true] - Initial handshake readiness.
   */
  constructor(ready = true) { super(); this.ready = ready; this.headers = []; this.data = []; }
  /**
   * Record a block locator without performing network I/O.
   * @param {Buffer[]} locator - Requested chain locator.
   * @returns {void}
   */
  requestHeaders(locator) { this.headers.push(locator); }
  /**
   * Record a block inventory request without sending it.
   * @param {object[]} items - Requested inventory entries.
   * @returns {void}
   */
  requestData(items) { this.data.push(items); }
}

test('sync continues through three 500-block request windows without restarting', async t => {
  const peer=new Peer(),checkpoint=Buffer.alloc(32,7),downloaded=[];
  const index={ingest:async()=>{},ingestBatch:async blocks=>{downloaded.push(...blocks.map(b=>b.height));return blocks.map(b=>({blockHash:Buffer.from(hash256d(b.rawBlock.subarray(0,80))).reverse().toString('hex')}));},syncCheckpoint:()=>({height:41900,hash:checkpoint})};
  const sync=new PepecoinSync({peer,index,consensus:trusting});t.after(()=>sync.stop());sync.start();
  let previous=checkpoint;
  for(const count of [500,500,51]) {
    const headers=[];
    for(let i=0;i<count;i++) { const h=Buffer.alloc(80);previous.copy(h,4);headers.push(h);previous=hash256d(h); }
    const requests=peer.headers.length;
    peer.emit('message',{command:'headers',payload:Buffer.concat([varInt(count),...headers.flatMap(h=>[h,Buffer.from([0])])])});
    for(const header of headers) peer.emit('message',{command:'block',payload:header});
    for(let i=0;i<100 && peer.headers.length===requests;i++) await new Promise(resolve=>setImmediate(resolve));
    assert.equal(peer.headers.length,requests+1,'next page must be requested automatically');
    assert.deepEqual(peer.headers.at(-1),[previous]);
  }
  assert.equal(downloaded.length,1051);assert.equal(downloaded[0],41901);assert.equal(downloaded.at(-1),42951);
  let completed=false;sync.on('synced',()=>completed=true);peer.emit('message',{command:'headers',payload:Buffer.from([0])});assert.ok(completed);
});

test('sync requires a trusted checkpoint and requests headers from it', () => {
  const peer = new Peer(), checkpoint = Buffer.alloc(32, 1);
  const index = { ingest: async () => {}, ingestBatch: async () => [], syncCheckpoint: () => ({ height: 1_130_000, hash: checkpoint }) };
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  sync.start();
  assert.deepEqual(peer.headers, [[checkpoint]]);
  assert.throws(() => new PepecoinSync({ peer, index: { ingest: async () => {}, ingestBatch: async () => [] } }), /syncCheckpoint/);
});

test('sync starts after the Pepecoin genesis block when the index is empty', () => {
  const peer = new Peer();
  const index = {
    ingest: async () => {},
    ingestBatch: async () => [],
    syncCheckpoint: () => ({ height: -1, hash: Buffer.alloc(32) })
  };
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  sync.start();
  assert.equal(peer.headers.length, 1);
  assert.equal(peer.headers[0][0].toString('hex'),
    'aa5f2a8c7ff591b05c97ff93dbaa8d83a0e9ec428a6c376589d4b8480c1c9837');
});

test('sync limits each headers page to a peer-safe block request size', async () => {
  const peer = new Peer(), checkpoint = Buffer.alloc(32, 1);
  const index = {
    ingest: async () => {},
    ingestBatch: async () => [],
    syncCheckpoint: () => ({ height: 10, hash: checkpoint })
  };
  const { hash256d } = await import('../lib/pepenet-wire.js');
  const headers = [];
  let previous = checkpoint;
  for (let i = 0; i < 501; i++) {
    const header = Buffer.alloc(80);
    previous.copy(header, 4);
    headers.push(header, Buffer.from([0]));
    previous = hash256d(header);
  }
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  sync.start();
  peer.emit('message', {
    command: 'headers',
    payload: Buffer.concat([Buffer.from([0xfd, 0xf5, 0x01]), ...headers])
  });
  assert.equal(peer.data.length, 1);
  assert.equal(peer.data[0].length, 500);
  sync.stop();
});

test('sync downloads only a block that matches a linked announced header', async () => {
  const peer = new Peer(), ingested = [], checkpoint = Buffer.alloc(32, 1);
  const index = {
    ingest: async (raw, height) => ingested.push({ raw, height }),
    ingestBatch: async blocks => {
      for (const block of blocks) await index.ingest(block.rawBlock, block.height);
      return blocks.map(() => ({ blockHash: '00'.repeat(32) }));
    },
    syncCheckpoint: () => ({ height: 10, hash: checkpoint })
  };
  const header = Buffer.alloc(80); checkpoint.copy(header, 4); header.writeUInt32LE(100, 68);
  const transaction = Buffer.concat([Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(36), Buffer.from([0]), Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(8), Buffer.from([0]), Buffer.alloc(4)]);
  const rawBlock = Buffer.concat([header, Buffer.from([1]), transaction]);
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  const downloaded = new Promise(resolve => sync.once('block', resolve));
  sync.start();
  peer.emit('message', { command: 'headers', payload: Buffer.concat([Buffer.from([1]), header, Buffer.from([0])]) });
  assert.equal(peer.data[0][0].type, 2);
  peer.emit('message', { command: 'block', payload: rawBlock });
  const result = await downloaded;
  assert.equal(result.height, 11);
  assert.equal(ingested.length, 1);
  assert.equal(ingested[0].height, 11);
});

test('sync waits for announced blocks before stopping on an empty header response', async () => {
  const peer = new Peer(), ingested = [], checkpoint = Buffer.alloc(32, 1);
  const index = {
    ingest: async (raw, height) => {
      await new Promise(resolve => setTimeout(resolve, 5));
      ingested.push({ raw, height });
    },
    ingestBatch: async blocks => {
      for (const block of blocks) await index.ingest(block.rawBlock, block.height);
      return blocks.map(() => ({ blockHash: '00'.repeat(32) }));
    },
    syncCheckpoint: () => ({ height: 10, hash: checkpoint })
  };
  const header = Buffer.alloc(80);
  checkpoint.copy(header, 4);
  const transaction = Buffer.concat([
    Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(36), Buffer.from([0]),
    Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(8), Buffer.from([0]),
    Buffer.alloc(4)
  ]);
  const rawBlock = Buffer.concat([header, Buffer.from([1]), transaction]);
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  let synced = false;
  sync.once('synced', () => { synced = true; });
  sync.start();
  peer.emit('message', { command: 'headers', payload: Buffer.concat([Buffer.from([1]), header, Buffer.from([0])]) });
  peer.emit('message', { command: 'headers', payload: Buffer.from([0]) });
  assert.equal(synced, false);
  peer.emit('message', { command: 'block', payload: rawBlock });
  await new Promise(resolve => sync.once('block', resolve));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(synced, false, 'unsolicited empty headers cannot mark a page complete');
  assert.equal(peer.headers.length, 2, 'next page is requested without a restart');
  peer.emit('message', { command: 'headers', payload: Buffer.from([0]) });
  assert.equal(synced, true);
  assert.equal(ingested.length, 1);
});

test('sync can be stopped when its peer supervisor needs to retry', () => {
  const peer = new Peer();
  const index = {
    ingest: async () => {},
    ingestBatch: async () => [],
    syncCheckpoint: () => ({ height: 10, hash: Buffer.alloc(32, 1) })
  };
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  sync.start();
  sync.stop();
  peer.emit('message', { command: 'headers', payload: Buffer.from([0]) });
  assert.equal(peer.headers.length, 1);
});

test('stopping before peer readiness does not start a later request', () => {
  const peer = new Peer(false);
  const index = {
    ingest: async () => {},
    ingestBatch: async () => [],
    syncCheckpoint: () => ({ height: 10, hash: Buffer.alloc(32, 1) })
  };
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  sync.start();
  sync.stop();
  peer.ready = true;
  peer.emit('ready');
  assert.equal(peer.headers.length, 0);
});

test('stopping a sync clears its request watchdog', () => {
  const peer = new Peer();
  const index = {
    ingest: async () => {},
    ingestBatch: async () => [],
    syncCheckpoint: () => ({ height: 10, hash: Buffer.alloc(32, 1) })
  };
  const sync = new PepecoinSync({ peer, index, consensus: trusting });
  let errors = 0;
  sync.on('error', () => { errors++; });
  sync.start();
  sync.stop();
  assert.equal(errors, 0);
});

test('default consensus rejects a zero-work header page before requesting any block body', () => {
  const peer = new Peer(), checkpoint = Buffer.alloc(32, 3), errors = [];
  const index = { ingest: async () => {}, ingestBatch: async () => [], syncCheckpoint: () => ({ height: 500_000, hash: checkpoint }) };
  const sync = new PepecoinSync({ peer, index });
  sync.on('error', error => errors.push(error.message));
  sync.start();
  // A dishonest peer's fabricated block at the easiest target, paying anything it likes.
  const header = Buffer.alloc(80);
  header.writeUInt32LE((0x3f << 16) | 4, 0); checkpoint.copy(header, 4);
  header.writeUInt32LE(Math.floor(Date.now() / 1000), 68); header.writeUInt32LE(0x1e0fffff, 72);
  peer.emit('message', { command: 'headers', payload: Buffer.concat([varInt(1), header, Buffer.from([0])]) });
  assert.equal(peer.data.length, 0, 'no block body may be requested for an invalid header');
  assert.match(errors[0], /proof-of-work|AuxPoW/);
  sync.stop();
});

test('block bodies that do not match their header Merkle root are never buffered', () => {
  const peer = new Peer(), checkpoint = Buffer.alloc(32, 4);
  const index = { ingest: async () => {}, ingestBatch: async () => [], syncCheckpoint: () => ({ height: 10, hash: checkpoint }) };
  const sync = new PepecoinSync({ peer, index, consensus: { ...trusting, checkBlock: () => { throw new Error('bad body'); } } });
  sync.start();
  const header = Buffer.alloc(80); checkpoint.copy(header, 4);
  peer.emit('message', { command: 'headers', payload: Buffer.concat([varInt(1), header, Buffer.from([0])]) });
  peer.emit('message', { command: 'block', payload: Buffer.concat([header, Buffer.alloc(1024 * 1024)]) });
  assert.equal(sync.pendingBytes, 0);
  sync.stop();
});
