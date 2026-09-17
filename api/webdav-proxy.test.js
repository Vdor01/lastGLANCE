import { describe, it, expect, vi } from 'vitest'

// Mock DNS so hostname-based cases are deterministic and offline. Literal IPs
// bypass the mock's table and use the same literal-parse behavior as the real
// getaddrinfo (no network query for literals either way).
const dnsTable = {
  localhost: [{ address: '127.0.0.1', family: 4 }],
  'nas.rebind.example': [{ address: '10.0.0.5', family: 4 }],
  'metadata.rebind.example': [{ address: '93.184.216.34', family: 4 }, { address: '169.254.169.254', family: 4 }],
  'dav.example.com': [{ address: '93.184.216.34', family: 4 }],
  'dual.example.com': [{ address: '2606:4700::1111', family: 6 }, { address: '93.184.216.34', family: 4 }],
}
vi.mock('dns/promises', async importOriginal => {
  const real = await importOriginal()
  return {
    ...real,
    lookup: async (hostname, opts) => {
      if (dnsTable[hostname]) return dnsTable[hostname]
      return real.lookup(hostname, opts)
    },
  }
})

const {
  validateProxyUrl, isPrivateIPv4, isPrivateIPv6,
  isAlwaysBlockedIPv4, isAlwaysBlockedIPv6,
} = await import('./webdav-proxy.js')

// The two postures, passed explicitly so a test never depends on whether the
// suite happens to be running with VERCEL set.
const HOSTED = { allowPrivate: false }
const SELF_HOSTED = { allowPrivate: true }

const PRIVATE_ERR = 'Private/reserved addresses are not allowed'

describe('isPrivateIPv4', () => {
  it.each([
    '0.1.2.3', '10.0.0.1', '10.255.255.255', '100.64.0.1', '100.127.255.255',
    '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.1', '192.168.0.1', '198.18.0.1', '198.19.255.255', '224.0.0.1', '255.255.255.255',
  ])('blocks %s', ip => {
    expect(isPrivateIPv4(ip)).toBe(true)
  })

  it.each([
    '8.8.8.8', '93.184.216.34', '100.63.255.255', '100.128.0.1', '172.15.0.1',
    '172.32.0.1', '192.167.0.1', '192.169.0.1', '198.17.0.1', '198.20.0.1', '223.255.255.255',
  ])('allows %s', ip => {
    expect(isPrivateIPv4(ip)).toBe(false)
  })

  it('refuses unparseable input rather than allowing it', () => {
    expect(isPrivateIPv4('not-an-ip')).toBe(true)
    expect(isPrivateIPv4('1.2.3')).toBe(true)
    expect(isPrivateIPv4('1.2.3.999')).toBe(true)
  })
})

describe('isPrivateIPv6', () => {
  it.each([
    '::', '::1', 'fe80::1', 'febf::1', 'fc00::1', 'fd12:3456::1', 'ff02::1',
    // IPv4-mapped, both renderings: dns.lookup's dotted form and the
    // WHATWG-URL-normalized hex form of ::ffff:127.0.0.1
    '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:192.168.1.5', '::ffff:c0a8:105',
    'fe80::1%eth0', // zone id stripped, still link-local
  ])('blocks %s', ip => {
    expect(isPrivateIPv6(ip)).toBe(true)
  })

  it.each([
    '2606:4700::1111', '2001:4860:4860::8888',
    '::ffff:8.8.8.8', '::ffff:808:808', // mapped PUBLIC v4 is fine
  ])('allows %s', ip => {
    expect(isPrivateIPv6(ip)).toBe(false)
  })
})

describe('validateProxyUrl', () => {
  it('rejects non-http(s) schemes in either posture', async () => {
    await expect(validateProxyUrl('ftp://example.com/x', SELF_HOSTED)).rejects.toThrow('Only http and https')
    await expect(validateProxyUrl('file:///etc/passwd', HOSTED)).rejects.toThrow('Only http and https')
  })

  it('rejects malformed URLs', async () => {
    await expect(validateProxyUrl('not a url', SELF_HOSTED)).rejects.toThrow('Invalid URL')
  })

  it.each([
    'http://10.0.0.1/dav/',
    'http://192.168.1.5/dav/',
    'http://172.16.0.1/dav/',
    'http://127.0.0.1/dav/',
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost/dav/',
    'http://[::1]/dav/',
    'http://[fe80::1]/dav/',
    'http://[::ffff:127.0.0.1]/dav/', // URL normalizes to [::ffff:7f00:1]
  ])('blocks %s on the hosted deployment', async url => {
    await expect(validateProxyUrl(url, HOSTED)).rejects.toThrow(PRIVATE_ERR)
  })

  it.each([
    // WHATWG URL canonicalizes exotic IPv4 encodings before validation ever
    // runs; these all become 127.0.0.1 and must stay blocked.
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://0x7f000001/',
  ])('blocks encoded-loopback %s on the hosted deployment', async url => {
    await expect(validateProxyUrl(url, HOSTED)).rejects.toThrow(PRIVATE_ERR)
  })

  it('blocks a public hostname whose DNS answer is a private address', async () => {
    await expect(validateProxyUrl('https://nas.rebind.example/dav/', HOSTED)).rejects.toThrow(PRIVATE_ERR)
  })

  it('blocks when ANY resolved address is private, even alongside public ones', async () => {
    await expect(validateProxyUrl('https://metadata.rebind.example/dav/', HOSTED)).rejects.toThrow(PRIVATE_ERR)
  })

  it('pins a public hostname to its validated address', async () => {
    const { pinned } = await validateProxyUrl('https://dav.example.com/dav/', HOSTED)
    expect(pinned).toEqual([{ address: '93.184.216.34', family: 4 }])
  })

  it('keeps EVERY validated address, IPv4 first, so family fallback survives', async () => {
    // Pinning to one hand-picked address would forgo Node's fallback, so a host
    // advertising a broken AAAA beside a working A would lose the IPv4 path.
    const { pinned } = await validateProxyUrl('https://dual.example.com/dav/', HOSTED)
    expect(pinned).toEqual([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:4700::1111', family: 6 },
    ])
  })

  it('pins public IP literals without a DNS query', async () => {
    const v4 = await validateProxyUrl('https://93.184.216.34/dav/', HOSTED)
    expect(v4.pinned).toEqual([{ address: '93.184.216.34', family: 4 }])
    const v6 = await validateProxyUrl('https://[2606:4700::1111]/dav/', HOSTED)
    expect(v6.pinned[0].family).toBe(6)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// The self-hosted posture. It used to skip resolution altogether, which meant a
// self-hosted instance validated nothing (the cloud metadata endpoint was
// reachable through it) and got no rebinding pin either, since the pin is
// derived from that same resolution. Allowing the LAN does not require allowing
// everything, and these two blocks are the claim that it does not.
// ─────────────────────────────────────────────────────────────────────────────
describe('isAlwaysBlockedIPv4 / isAlwaysBlockedIPv6', () => {
  it.each([
    '0.1.2.3', '169.254.169.254', '192.0.0.1', '198.18.0.1', '198.19.255.255',
    '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
  ])('%s can never be reached, in any posture', ip => {
    expect(isAlwaysBlockedIPv4(ip)).toBe(true)
    expect(isPrivateIPv4(ip)).toBe(true) // and is a subset of the private set
  })

  it.each([
    '10.0.0.1', '172.16.0.1', '192.168.1.5', '127.0.0.1', '100.64.0.1',
  ])('%s is private but reachable on a self-host', ip => {
    expect(isAlwaysBlockedIPv4(ip)).toBe(false)
    expect(isPrivateIPv4(ip)).toBe(true)
  })

  it('refuses unparseable input in either posture', () => {
    expect(isAlwaysBlockedIPv4('not-an-ip')).toBe(true)
    expect(isAlwaysBlockedIPv4('1.2.3')).toBe(true)
    expect(isAlwaysBlockedIPv4('1.2.3.999')).toBe(true)
  })

  it('separates v6 loopback and ULA from link-local, multicast and unspecified', () => {
    expect(isAlwaysBlockedIPv6('::1')).toBe(false)      // private, reachable
    expect(isAlwaysBlockedIPv6('fd00::1')).toBe(false)  // ULA, reachable
    expect(isAlwaysBlockedIPv6('::')).toBe(true)
    expect(isAlwaysBlockedIPv6('fe80::1')).toBe(true)
    expect(isAlwaysBlockedIPv6('ff02::1')).toBe(true)
    expect(isAlwaysBlockedIPv6('::ffff:169.254.169.254')).toBe(true)
  })
})

describe('validateProxyUrl, self-hosted posture', () => {
  // No self-hoster loses a destination they have today.
  it.each([
    ['a NAS on the LAN', 'http://192.168.1.5/dav/'],
    ['a Docker host on 10/8', 'http://10.0.0.1/dav/'],
    ['the Docker bridge', 'http://172.17.0.1/dav/'],
    ['a Tailscale node', 'http://100.101.102.103/dav/'],
    ['the same machine', 'http://127.0.0.1/dav/'],
    ['localhost by name', 'http://localhost/dav/'],
    ['v6 loopback', 'http://[::1]/dav/'],
    ['a public host', 'https://dav.example.com/dav/'],
  ])('still reaches %s', async (_label, url) => {
    const { pinned } = await validateProxyUrl(url, SELF_HOSTED)
    expect(pinned.length).toBeGreaterThan(0)
  })

  // But it is no longer an unguarded relay.
  it.each([
    ['the cloud metadata endpoint', 'http://169.254.169.254/latest/meta-data/'],
    ['multicast', 'http://224.0.0.1/'],
    ['reserved space', 'http://240.0.0.1/'],
    ['benchmarking space', 'http://198.18.0.1/'],
    ['the unspecified address', 'http://0.0.0.0/'],
    ['v6 link-local', 'http://[fe80::1]/dav/'],
  ])('now refuses %s', async (_label, url) => {
    await expect(validateProxyUrl(url, SELF_HOSTED)).rejects.toThrow(PRIVATE_ERR)
  })

  it('refuses a public hostname whose DNS answer hides the metadata endpoint', async () => {
    // The rebinding shape. Self-hosters now get this check, and the pin, which
    // they previously did not because resolution was skipped entirely.
    await expect(validateProxyUrl('https://metadata.rebind.example/dav/', SELF_HOSTED))
      .rejects.toThrow(PRIVATE_ERR)
  })

  it('pins the connection on a self-host too, not only on Vercel', async () => {
    const { pinned } = await validateProxyUrl('http://192.168.1.5/dav/', SELF_HOSTED)
    expect(pinned).toEqual([{ address: '192.168.1.5', family: 4 }])
  })
})
