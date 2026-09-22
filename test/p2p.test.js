/**
 * Public-peer framing, handshake, peer isolation, and exact-transaction relay receipt tests.
 * Network fixtures are simulated or loopback-only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { encodeMessage, inventoryPayload, MessageDecoder, MultiPeerManager, parseAddresses, parseHeaders, parseInventory, PepecoinPeer, versionPayload } from '../lib/pepenet-p2p.js';

test('sync responses are isolated to the selected peer and close cannot refill connections', () => {
  const manager = new MultiPeerManager({ archivePeers: [], seeds: [] });
  const fake = height => Object.assign(new EventEmitter(), { ready:true,remoteServices:1n,remoteStartHeight:height,requestHeaders(){},close(){this.emit('close');} });
  const a=fake(100),b=fake(200),messages=[];
  manager.connectTo(a);manager.connectTo(b);manager.on('message',m=>messages.push(m));
  manager.requestHeaders([Buffer.alloc(32)]);
  assert.equal(manager.syncPeer,b);
  a.emit('message',{command:'headers',payload:Buffer.from([0])});
  b.emit('message',{command:'headers',payload:Buffer.from([0])});
  assert.equal(messages.length,1);
  manager.close();assert.equal(manager.peers.size,0);assert.equal(manager.readyPeers.size,0);
  manager.connectTo(fake(300));assert.equal(manager.peers.size,0);
});

test('Pepecoin P2P frames round-trip across partial reads', () => {
  const frame = encodeMessage('ping', Buffer.from('nonce'));
  const decoder = new MessageDecoder();
  assert.deepEqual(decoder.push(frame.subarray(0, 11)), []);
  assert.deepEqual(decoder.push(frame.subarray(11)), [{ command: 'ping', payload: Buffer.from('nonce') }]);
});

test('version payload advertises the connected peer address', () => {
  const payload = versionPayload(123, '54.68.211.33', 33874);
  assert.equal(payload.readInt32LE(0), 70015);
  assert.equal(payload.readBigUInt64LE(20), 0n);
  assert.equal(payload.readUInt16BE(44), 33874);
  assert.deepEqual([...payload.subarray(40, 44)], [54, 68, 211, 33]);
  assert.equal(payload.readBigUInt64LE(46), 1n);
  assert.equal(payload.readBigUInt64LE(72) !== 0n, true);
});

test('P2P inventory and headers decoders validate wire framing', () => {
  const hash = Buffer.alloc(32, 9), inventory = inventoryPayload([{ type: 2, hash }]);
  assert.deepEqual(parseInventory(inventory), [{ type: 2, hash }]);
  assert.throws(() => parseInventory(Buffer.from([1])), /Invalid inventory payload/);
  const header = Buffer.alloc(80); header.writeUInt32LE(42, 68); header.writeUInt32LE(0x1e0ffff0, 72);
  const headers = parseHeaders(Buffer.concat([Buffer.from([1]), header, Buffer.from([0])]));
  assert.equal(headers.length, 1);
  assert.equal(headers[0].time, 42);
  assert.equal(parseHeaders(Buffer.concat([Buffer.from([1]), header, Buffer.from([1])])).length, 1);
});

test('P2P address decoder keeps only public IPv4 peers', () => {
  const publicAddress = Buffer.alloc(30);
  publicAddress.writeBigUInt64LE(1n, 4);
  publicAddress.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 98, 80, 234, 184], 12);
  publicAddress.writeUInt16BE(33874, 28);
  const localAddress = Buffer.from(publicAddress);
  localAddress.set([127, 0, 0, 1], 24);
  assert.deepEqual(parseAddresses(Buffer.concat([Buffer.from([2]), publicAddress, localAddress])), [{
    host: '98.80.234.184', port: 33874, services: 1n
  }]);
});

test('headers decoder skips Pepecoin AuxPoW data', () => {
  const header = Buffer.alloc(80);
  header.writeUInt32LE(0x100, 0);
  const coinbase = Buffer.concat([
    Buffer.alloc(4, 1), Buffer.from([1]), Buffer.alloc(36),
    Buffer.from([0]), Buffer.alloc(4), Buffer.from([1]),
    Buffer.alloc(8), Buffer.from([0]), Buffer.alloc(4)
  ]);
  const auxpow = Buffer.concat([
    coinbase, Buffer.alloc(32), Buffer.from([0]), Buffer.alloc(4),
    Buffer.from([0]), Buffer.alloc(4), Buffer.alloc(80)
  ]);
  const parsed = parseHeaders(Buffer.concat([
    Buffer.from([1]), header, auxpow, Buffer.from([0])
  ]));
  assert.equal(parsed.length, 1);
});

test('peer manager relays a withdrawal through every ready peer', async () => {
  const manager = new MultiPeerManager();
  manager.readyPeers.add({ broadcastTransaction: async () => {} });
  manager.readyPeers.add({ broadcastTransaction: async () => {} });
  assert.equal(await manager.broadcastTransaction(Buffer.from([1, 2, 3])), 2);
});

/**
 * Create a peer with a fake socket that delivers decoded writes to a responder.
 * @param {function(PepecoinPeer, object): void} respond - Simulates remote responses.
 * @returns {PepecoinPeer} Peer with no real network connection.
 */
function relayFixture(respond) {
  const peer = new PepecoinPeer({ host: 'test.invalid' });
  const decoder = new MessageDecoder();
  peer.socket = {
    destroyed: false,
    write(frame, callback) {
      queueMicrotask(() => {
        for (const message of decoder.push(frame)) respond(peer, message);
        callback?.();
      });
    }
  };
  return peer;
}

test('relay succeeds only when peer serves the exact transaction back', async () => {
  const raw = Buffer.from('test transaction');
  const commands = [];
  const peer = relayFixture((p, m) => {
    commands.push(m.command);
    if (m.command === 'ping') p.emit('message', { command: 'pong', payload: m.payload });
    if (m.command === 'getdata') p.emit('message', { command: 'tx', payload: raw });
  });
  await peer.broadcastTransaction(raw);
  assert.deepEqual(commands, ['tx', 'ping', 'getdata']);
  assert.equal(peer.listenerCount('message'), 0);
});

test('relay surfaces a rejection for this tx and ignores unrelated rejects', async () => {
  const raw = Buffer.from('invalid test transaction');
  const hash = createHash('sha256').update(createHash('sha256').update(raw).digest()).digest();
  const reason = Buffer.from('mandatory-script-verify-flag-failed');
  const peer = relayFixture((p, m) => {
    if (m.command !== 'tx') return;
    const reject = txHash => p.emit('message', { command: 'reject', payload: Buffer.concat([
      Buffer.from([2, 116, 120, 0x10, reason.length]), reason, txHash
    ]) });
    reject(Buffer.alloc(32));
    reject(hash);
  });
  await assert.rejects(peer.broadcastTransaction(raw), /mandatory-script-verify-flag-failed/);
  assert.equal(peer.listenerCount('message'), 0);
});

test('socket write success without a peer receipt is not relay success', async () => {
  const peer = relayFixture(() => {});
  await assert.rejects(peer.broadcastTransaction(Buffer.from('test'), { timeoutMs: 20 }), /confirmation is unknown/);
  assert.equal(peer.listenerCount('message'), 0);
});

test('relay fails if peer reports that the transaction was not retained', async () => {
  const peer = relayFixture((p, m) => {
    if (m.command === 'ping') p.emit('message', { command: 'pong', payload: m.payload });
    if (m.command === 'getdata') p.emit('message', { command: 'notfound', payload: m.payload });
  });
  await assert.rejects(peer.broadcastTransaction(Buffer.from('test')), /did not retain/);
});

test('peer manager accepts a peer that is already connected', () => {
  const manager = new MultiPeerManager();
  const peer = new (class extends EventEmitter {
    constructor() { super(); this.ready = true; }
    close() {}
  })();
  let ready = 0;
  manager.on('ready', () => { ready++; });
  manager.connectTo(peer);
  assert.equal(ready, 1);
  assert.equal(manager.hasReadyPeers(), true);
});

test('peer connect completes only after the version/verack handshake', async () => {
  const server = net.createServer(socket => {
    const decoder = new MessageDecoder();
    socket.on('data', data => {
      for (const message of decoder.push(data)) if (message.command === 'version') {
        socket.write(encodeMessage('version', versionPayload(0)));
        socket.write(encodeMessage('verack'));
      }
    });

    test('transaction relay detects a peer reject message', async () => {
      const peer = new PepecoinPeer({ host: '127.0.0.1', port: 1 });
      const result = peer.waitForReject(100);
      const reason = Buffer.from('mandatory-script-verify-flag-failed');
      peer.emit('message', {
        command: 'reject',
        payload: Buffer.concat([Buffer.from([2, 116, 120, 0x10, reason.length]), reason])
      });
      await assert.rejects(result, /mandatory-script-verify-flag-failed/);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port, peer = new PepecoinPeer({ host: '127.0.0.1', port, timeoutMs: 1_000 });
  await peer.connect();
  assert.equal(peer.ready, true);
  assert.equal(peer.remoteStartHeight, 0);
  peer.close(); await new Promise(resolve => server.close(resolve));
});
