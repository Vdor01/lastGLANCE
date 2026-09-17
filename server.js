import http from 'http'
import { URL } from 'url'
import handler, { defaultAllowPrivate } from './api/webdav-proxy.js'

// This server IS the self-hosted deployment (Dockerfile runs it beside nginx),
// so it takes the self-host posture: WebDAV targets on the operator's own
// network are reachable, while the cloud metadata endpoint and other reserved
// ranges are refused and every connection is pinned to a validated address.
// Set WEBDAV_PROXY_BLOCK_PRIVATE=1 for the cloud lock-down instead.

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost')
  req.query = Object.fromEntries(u.searchParams)

  // Adapt Node.js ServerResponse to the Vercel-style res.status().send() interface
  res.status = (code) => {
    res.statusCode = code
    return {
      json:  (obj)  => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)) },
      send:  (body) => res.end(body),
      end:   ()     => res.end(),
    }
  }

  handler(req, res).catch((err) => {
    console.error('[proxy] unhandled error:', err)
    if (!res.headersSent) { res.statusCode = 502; res.end('Bad Gateway') }
  })
})

server.listen(3001, '127.0.0.1', () => {
  const posture = defaultAllowPrivate()
    ? 'private/LAN targets allowed; set WEBDAV_PROXY_BLOCK_PRIVATE=1 to refuse them'
    : 'private/LAN targets refused'
  console.log(`[proxy] listening on 127.0.0.1:3001 [${posture}]`)
})
