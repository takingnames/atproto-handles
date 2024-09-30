import * as oauth from 'https://cdn.jsdelivr.net/npm/oauth4webapi@2.17.0/+esm'

class Client {
  constructor(loginData, privateKey, publicKey) {
    this._ld = loginData;

    this._privKey = privateKey;
    this._pubKey = publicKey;
    this._nonce = this._ld.dpopNonce;

  }

  get handle() {
    return this._ld.handle;
  }

  get did() {
    return this._ld.did;
  }

  async resolveHandle(handle) {
    const uri = `${this._ld.apiServer}/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`
    const res = await this.fetch(uri);
    const data = await res.json();
    return data.did;
  }

  async updateHandle(handle) {
    const uri = `${this._ld.apiServer}/xrpc/com.atproto.identity.updateHandle`
    const res = await this.fetch(uri, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        handle,
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(body);
    }
  }

  async fetch(uri, opt) {

    const protectedResourceRequest = () => {

      const dpop = {
        privateKey: this._privKey,
        publicKey: this._pubKey,
        nonce: this._dpopNonce,
      };

      let method = 'GET';
      if (opt?.method) {
        method = opt.method;
      }

      return oauth.protectedResourceRequest(
        this._ld.accessToken,
        method,
        new URL(uri),
        opt?.headers,
        opt?.body,
        { DPoP: dpop }
      );
    }

    let res = await protectedResourceRequest();
    
    if (!res.ok) {
      const body = await res.json();
      if (body.error === 'use_dpop_nonce') {
        this._dpopNonce = res.headers.get('DPoP-Nonce');
        res = await protectedResourceRequest();
      }
      else {
        throw new Error(JSON.stringify(body));
      }
    }

    return res;
  }
}

async function lookupDid(domain) {

  const dnsPromise = lookupDidDns(domain);
  const httpPromise = lookupDidHttp(domain);

  let did = await Promise.any([ dnsPromise, httpPromise ]);

  if (!did) {
    const results = await Promise.all([ dnsPromise, httpPromise ]);
    did = results[0] ? results[0] : results[1];
  }

  return did;
}

async function lookupDidHttp(domain) {
  const uri = `https://${domain}/.well-known/atproto-did`;

  let res;
  try {
    res = await fetch(uri);
  }
  catch (e) {
    return null;
  }

  if (!res.ok) {
    return null;
  }

  const did = await res.text();
  return did;
}

async function lookupDidDns(domain) {

  const verifDomain = `_atproto.${domain}`;

  const res = await lookupDnsRecords(verifDomain, 'TXT');

  let did;

  if (!res.Answer || res.Answer.length < 1) {
    return null;
  }

  for (const record of res.Answer) {
    if (record.name === verifDomain) {
      // TODO: not sure what format this is supposed to be
      const didTxt = JSON.parse(record.data);
      const didParts = didTxt.split('=');
      did = didParts[1];
      break;
    }
  }

  return did;
}

const dohServer = 'https://cloudflare-dns.com';
async function lookupDnsRecords(domain, type) {
  const uri = `${dohServer}/dns-query?name=${domain}&type=${type}`;
  const recRes = await fetch(uri, {
    headers: {
      'Accept': 'application/dns-json',
    },
  });
  const recs = await recRes.json();
  return recs;
}

async function resolveDid(did) {

  if (!did.startsWith('did:plc')) {
    throw new Error("Unsupported did type: " + did);
  }

  const uri = `https://plc.directory/${did}`;
  const didDataRes = await fetch(uri);
  const didData = await didDataRes.json();

  return didData;
}

function logout() {
  localStorage.removeItem('login_data');
}

async function login(handleOrServer) {

  let handle;
  let as;
  let didData;

  // TODO: we'll need this code if we ever want to support providers other than
  // bsky.social
  //const did = await lookupDid(handleOrServer);
  let did;
  if (did) {
    didData = await resolveDid(did);
    handle = didData.alsoKnownAs[0].split('at://')[1];
    as = await lookupAuthServer(didData);
  }
  else {
    handle = null;
    const res = await fetch(`https://${handleOrServer}/.well-known/oauth-authorization-server`);
    as = await res.json();
  }

  const cl = await getClientMeta();
  const redirectUri = cl.redirect_uris[0];

  const codeVerifier = oauth.generateRandomCodeVerifier()
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)

  const state = oauth.generateRandomState();
  const authUri = `${as.authorization_endpoint}?client_id=${cl.client_id}&redirect_uri=${redirectUri}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256&response_type=code&scope=atproto`;

  const dpopKeyPair = await oauth.generateKeyPair("RS256", {
    extractable: true,
  });

  const params = {
    response_type: "code",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    client_id: cl.client_id,
    state,
    redirect_uri: cl.redirect_uris[0],
    scope: cl.scope,
  }

  if (handle) {
    params.login_hint = handle;
  }

  const makeParRequest = async (dpopNonce) => {
    return oauth.pushedAuthorizationRequest(
      as,
      cl,
      params,
      {
        DPoP: {
          privateKey: dpopKeyPair.privateKey,
          publicKey: dpopKeyPair.publicKey,
          nonce: dpopNonce,
        },
      },
    );
  };

  let res = await makeParRequest();

  let par = await res.json();

  let dpopNonce;

  if (!res.ok) {
    if (par.error === 'use_dpop_nonce') {
      dpopNonce = res.headers.get('DPoP-Nonce');
      res = await makeParRequest(dpopNonce);
      par = await res.json();
    }
  }

  const authReq = {
    handle,
    did,
    didData,
    as,
    client: cl,
    codeVerifier: codeVerifier,
    redirectUri,
    dpopPrivateJwk: JSON.stringify(
      await crypto.subtle.exportKey("jwk", dpopKeyPair.privateKey),
    ),
    dpopPublicJwk: JSON.stringify(
      await crypto.subtle.exportKey("jwk", dpopKeyPair.publicKey),
    ),
    dpopNonce,
  };

  //await kvStore.set(`oauth_state/${state}`, authReq);
  localStorage.setItem(state, JSON.stringify(authReq));

  const redirUri = new URL(as.authorization_endpoint);
  redirUri.searchParams.set('request_uri', par.request_uri);
  redirUri.searchParams.set('client_id', cl.client_id);

  window.location.href = redirUri.toString();
}

async function checkLogin() { 

  const loginDataJson = localStorage.getItem('login_data');
  if (loginDataJson) {
    const ld = JSON.parse(loginDataJson);
    const { privateKey, publicKey } = await importJwks(ld.dpopPrivateJwk, ld.dpopPublicJwk); 
    return new Client(ld, privateKey, publicKey);
  }

  const url = new URL(window.location);
  const paramsState = new URLSearchParams(url.search);

  const state = paramsState.get('state');
  if (!state) {
    return null;
  }

  const authRequestJson = localStorage.getItem(state);
  localStorage.removeItem(state);

  if (!authRequestJson) {
    throw new Error("No such auth request");
  }

  const authReq = JSON.parse(authRequestJson);

  const params = oauth.validateAuthResponse(authReq.as, authReq.client, url, state);
  if (oauth.isOAuth2Error(params)) {
    console.error('Error Response', params)
    throw new Error()
  }

  const { privateKey, publicKey } = await importJwks(authReq.dpopPrivateJwk, authReq.dpopPublicJwk); 

  const authorizationCodeGrantRequest = (dpopNonce) => {
    const dpop = {
      privateKey,
      publicKey,
      nonce: dpopNonce,
    };
    return oauth.authorizationCodeGrantRequest(
      authReq.as, authReq.client, params, authReq.redirectUri, authReq.codeVerifier, { DPoP: dpop });
  };

  let dpopNonce = authReq.dpopNonce;
  let res = await authorizationCodeGrantRequest(dpopNonce);

  let body = await res.json();

  if (!res.ok) {
    if (body.error === 'use_dpop_nonce') {
      dpopNonce = res.headers.get('DPoP-Nonce');
      res = await authorizationCodeGrantRequest(dpopNonce);
      body = await res.json();
    }
  }

  if (!res.ok) {
    throw new Error("Failed for some reason");
  }

  const did = body.sub;

  if (authReq.did && authReq.did !== did) {
    throw new Error("Mismatched DIDs");
  }

  let didData = authReq.didData;
  if (!didData) {
    didData = await resolveDid(did);
  }

  const handle = didData.alsoKnownAs[0].split('at://')[1];

  window.history.replaceState(null, '', window.location.pathname);

  const loginData = {
    handle,
    did,
    apiServer: didData.service[0].serviceEndpoint,
    accessToken: body.access_token,
    dpopPrivateJwk: authReq.dpopPrivateJwk,
    dpopPublicJwk: authReq.dpopPublicJwk,
    dpopNonce,
  };

  localStorage.setItem('login_data', JSON.stringify(loginData));

  return new Client(loginData, privateKey, publicKey);
}

async function lookupAuthServer(didData) {
  const uri = `${didData.service[0].serviceEndpoint}/.well-known/oauth-protected-resource`;
  const res = await fetch(uri);
  const data = await res.json();
  const authServer = data.authorization_servers[0];

  const issuer = new URL(authServer);
  const as = await oauth
    .discoveryRequest(issuer, { algorithm: 'oauth2' })
    .then((response) => oauth.processDiscoveryResponse(issuer, response))

  return as;
}

async function getClientMeta() {
  const urlParts = import.meta.url.split('/');
  const urlDir = urlParts.slice(0, -1).join('/') + '/';
  const mdFilename = inProd() ? 'client-metadata.json' : 'dev-client-metadata.json';
  return fetch(urlDir + mdFilename).then(res => res.json());
}

function inProd() {
  return window.location.href.includes('github.io');
}

async function importJwks(privateJwk, publicJwk) {
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey(
      "jwk",
      JSON.parse(privateJwk),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["sign"],
    ),
    crypto.subtle.importKey(
      "jwk",
      JSON.parse(publicJwk),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"],
    ),
  ]);

  return {
    publicKey,
    privateKey,
  };
}

export {
  checkLogin,
  lookupDid,
  resolveDid,
  login,
  logout,
  inProd,
};
