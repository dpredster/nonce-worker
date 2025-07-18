addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // 1. Fetch the original response (from cache or origin)
  const response = await fetch(request)

  // 2. Generate a new, cryptographically secure nonce
  const cspNonce = generateNonce()

  // 3. Clone and modify headers
  const newHeaders = new Headers(response.headers)
  if (response.status !== 304) {
    // Set strict, nonce-based CSP
    newHeaders.set(
      'Content-Security-Policy',
      `default-src 'self'; \
       script-src 'nonce-${cspNonce}' 'strict-dynamic' https://challenges.cloudflare.com; \
       object-src 'none'; \
       upgrade-insecure-requests;`
    )
  } else {
    // Remove CSP headers on 304 to reuse previous nonce
    newHeaders.delete('Content-Security-Policy')
    newHeaders.delete('Content-Security-Policy-Report-Only')
  }

  // 4. If HTML, rewrite placeholder nonces in the body
  const contentType = response.headers.get('Content-Type') || ''
  if (contentType.includes('text/html')) {
    let text = await response.text()
    // Replace any nonce="..." with the freshly generated value
    text = text.replace(/nonce="[^"]*"/g, `nonce="${cspNonce}"`)
    return new Response(text, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    })
  }

  // 5. For non-HTML resources, just return as-is with updated headers
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  })
}

// Generate a Base64-encoded nonce using the Web Crypto API
function generateNonce() {
  const array = crypto.getRandomValues(new Uint8Array(16))
  let binary = ''
  array.forEach(byte => binary += String.fromCharCode(byte))
  return btoa(binary)
}
