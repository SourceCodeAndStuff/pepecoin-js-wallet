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

test('a frame with the wrong network magic is rejected instead of buffered forever', () => {
  const decoder = new MessageDecoder();
  assert.throws(() => decoder.push(Buffer.alloc(24, 0x41)), /network magic/);
  assert.equal(decoder.buffer.length, 0);
  assert.deepEqual(decoder.push(encodeMessage('ping', Buffer.from('ok'))), [{ command: 'ping', payload: Buffer.from('ok') }]);
});

test('headers pages above the protocol limit are rejected and AuxPoW parsing stays linear', () => {
  const plain = Buffer.alloc(81);
  assert.throws(() => parseHeaders(Buffer.concat([Buffer.from([0xfd, 0xd1, 0x07]), ...Array(2001).fill(plain)])), /Too many headers/);
  const header = Buffer.alloc(80); header.writeUInt32LE(0x100, 0);
  const coinbase = Buffer.concat([Buffer.alloc(4, 1), Buffer.from([1]), Buffer.alloc(36), Buffer.from([0]), Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(8), Buffer.from([0]), Buffer.alloc(4)]);
  const entry = Buffer.concat([header, coinbase, Buffer.alloc(32), Buffer.from([0]), Buffer.alloc(4), Buffer.from([0]), Buffer.alloc(4), Buffer.alloc(80), Buffer.from([0])]);
  const started = performance.now();
  const parsed = parseHeaders(Buffer.concat([Buffer.from([0xfd, 0xd0, 0x07]), ...Array(2000).fill(entry)]));
  assert.equal(parsed.length, 2000);
  assert.ok(parsed[0].auxpow.parentHeader.length === 80);
  assert.ok(performance.now() - started < 2000, 'parsing must not copy the payload per header');
});

test('addr gossip is bounded and queued behind configured peers', () => {
  const manager = new MultiPeerManager({ archivePeers: [], seeds: [], maxPeers: 0 });
  const peer = Object.assign(new EventEmitter(), { ready: true, remoteServices: 1n, close() {} });
  manager.connectTo(peer);
  const entry = n => { const b = Buffer.alloc(30); b.writeBigUInt64LE(1n, 4); b.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 98, (n >> 16) & 255, (n >> 8) & 255, n & 255], 12); b.writeUInt16BE(33874, 28); return b; };
  for (let m = 0; m < 5; m++) {
    const addrs = Array.from({ length: 1000 }, (_, i) => entry(m * 1000 + i));
    peer.emit('message', { command: 'addr', payload: Buffer.concat([Buffer.from([0xfd, 0xe8, 0x03]), ...addrs]) });
  }
  assert.ok(manager.candidates.length <= 2000);
  manager.close();
});

test('advertised network height is the median claim, so one peer cannot inflate it', () => {
  const manager = new MultiPeerManager({ archivePeers: [], seeds: [] });
  for (const height of [1000, 1001, 99_999_999]) manager.connectTo(Object.assign(new EventEmitter(), { ready: true, remoteServices: 1n, remoteStartHeight: height, requestHeaders() {}, close() {} }));
  assert.equal(manager.remoteStartHeight, 1001);
  manager.close();
});

test('an indexed tip is trusted only after independent peers confirm it', async () => {
  const tip = Buffer.alloc(32, 5);
  const witness = (host, reply) => Object.assign(new EventEmitter(), { host, ready: true, remoteServices: 1n, close() {},
    requestHeaders() { setImmediate(() => this.emit('message', { command: 'headers', payload: reply })); } });
  const agrees = Buffer.from([0]);
  const next = Buffer.alloc(81); tip.copy(next, 4);
  const forked = Buffer.alloc(81);
  const build = replies => { const m = new MultiPeerManager({ archivePeers: [], seeds: [] }); replies.forEach(([host, r]) => m.connectTo(witness(host, r))); return m; };
  const ok = build([['1.1.0.1', agrees], ['2.2.0.1', Buffer.concat([Buffer.from([1]), next])], ['3.3.0.1', Buffer.concat([Buffer.from([1]), forked])]]);
  assert.deepEqual(await ok.confirmTip(tip, { timeoutMs: 1000 }), { agreed: 2, asked: 3 });
  const sameSubnet = build([['1.1.0.1', agrees], ['1.1.0.2', agrees]]);
  await assert.rejects(sameSubnet.confirmTip(tip, { timeoutMs: 1000 }), /Only 1 of 1/);
  const disagree = build([['1.1.0.1', agrees], ['2.2.0.1', Buffer.concat([Buffer.from([1]), forked])]]);
  await assert.rejects(disagree.confirmTip(tip, { timeoutMs: 1000 }), /Only 1 of 2/);
  for (const m of [ok, sameSubnet, disagree]) m.close();
});

test('a single peer echoing a transaction back is not enough to report it as relayed', async () => {
  const manager = new MultiPeerManager();
  manager.readyPeers.add({ broadcastTransaction: async () => {} });
  manager.readyPeers.add({ broadcastTransaction: async () => { throw new Error('rejected'); } });
  await assert.rejects(manager.broadcastTransaction(Buffer.from([1])), /Only 1 Pepecoin peer/);
});

test('a post-handshake socket error without listeners closes the peer instead of crashing', async () => {
  const server = net.createServer(socket => {
    const decoder = new MessageDecoder();
    socket.on('error', () => {});
    socket.on('data', data => { for (const m of decoder.push(data)) if (m.command === 'version') { socket.write(encodeMessage('version', versionPayload(0))); socket.write(encodeMessage('verack')); } });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const peer = new PepecoinPeer({ host: '127.0.0.1', port: server.address().port, timeoutMs: 1000 });
  await peer.connect();
  assert.equal(peer.listenerCount('error'), 0);
  const socket = peer.socket;
  assert.doesNotThrow(() => socket.emit('error', new Error('connection reset')));
  assert.equal(peer.socket, null);
  await new Promise(resolve => server.close(resolve));
});
