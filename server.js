// ─────────────────────────────────────────────
// TikPublish — Backend Server
// Handles TikTok OAuth and serves the frontend
// Run with: node server.js
// ─────────────────────────────────────────────
require('dotenv').config();
const express  = require('express');
const fetch    = require('node-fetch');
const path     = require('path');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// In-memory token store (persisted to .token file)
const fs = require('fs');
const TOKEN_FILE = path.join(__dirname, '.token');

let tokenStore = {};
try {
  if (fs.existsSync(TOKEN_FILE)) {
    tokenStore = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    console.log('✓ Loaded existing token from .token file');
  }
} catch {}

function saveToken(data) {
  tokenStore = data;
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2));
}

// ─── Middleware ───────────────────────────────
app.use(express.json());
app.use(express.static(__dirname)); // serve index.html + assets

// ─── Config check ────────────────────────────
function getCreds() {
  return {
    clientKey:    process.env.TIKTOK_CLIENT_KEY,
    clientSecret: process.env.TIKTOK_CLIENT_SECRET,
    redirectUri:  `http://localhost:${PORT}/oauth/callback`,
  };
}

// ─────────────────────────────────────────────
// GET /auth/status
// Returns whether we have a valid token
// ─────────────────────────────────────────────
app.get('/auth/status', (req, res) => {
  const hasToken = !!(tokenStore.access_token);
  const expired  = tokenStore.expires_at && Date.now() > tokenStore.expires_at;
  res.json({
    connected:   hasToken && !expired,
    expired:     hasToken && expired,
    username:    tokenStore.username || null,
    open_id:     tokenStore.open_id  || null,
    expires_at:  tokenStore.expires_at || null,
  });
});

// ─────────────────────────────────────────────
// GET /auth/login
// Redirects browser to TikTok OAuth page
// ─────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const { clientKey, redirectUri } = getCreds();
  if (!clientKey) {
    return res.status(400).send('TIKTOK_CLIENT_KEY not set in .env — edit the .env file and restart server.js');
  }

  const state        = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Store both state and verifier for the callback
  tokenStore._state        = state;
  tokenStore._codeVerifier = codeVerifier;

  const params = new URLSearchParams({
    client_key:            clientKey,
    response_type:         'code',
    scope:                 'user.info.basic,video.publish,video.upload',
    redirect_uri:          redirectUri,
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256',
  });

  res.redirect('https://www.tiktok.com/v2/auth/authorize/?' + params.toString());
});

// ─────────────────────────────────────────────
// GET /oauth/callback
// TikTok redirects here after the user logs in
// ─────────────────────────────────────────────
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const { clientKey, clientSecret, redirectUri } = getCreds();

  if (error) {
    return res.send(`<script>window.opener.postMessage({type:'tt_error',error:'${error}'},'*');window.close();</script>`);
  }

  if (state !== tokenStore._state) {
    return res.send(`<script>window.opener.postMessage({type:'tt_error',error:'state_mismatch'},'*');window.close();</script>`);
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key:    clientKey,
        client_secret: clientSecret,
        code,
        grant_type:    'authorization_code',
        redirect_uri:  redirectUri,
        code_verifier: tokenStore._codeVerifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      throw new Error(tokenData.error_description || tokenData.error);
    }

    // Fetch user info
    let username = 'TikTok User';
    try {
      const userRes = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=display_name,avatar_url', {
        headers: { Authorization: 'Bearer ' + tokenData.access_token },
      });
      const userData = await userRes.json();
      username = userData.data?.user?.display_name || username;
    } catch {}

    saveToken({
      access_token:  tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      open_id:       tokenData.open_id,
      scope:         tokenData.scope,
      username,
      expires_at:    Date.now() + (tokenData.expires_in * 1000),
    });

    console.log(`✓ TikTok connected as ${username}`);

    // Close the popup and notify the parent window
    res.send(`
      <html><body style="font-family:sans-serif;background:#0a0a0f;color:#f0eeff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
        <div style="text-align:center">
          <div style="font-size:2rem;margin-bottom:12px">✓</div>
          <div style="font-size:1rem;color:#3ecf8e">Connected as ${username}!</div>
          <div style="font-size:.8rem;color:rgba(240,238,255,.45);margin-top:8px">This window will close…</div>
        </div>
        <script>
          window.opener && window.opener.postMessage({type:'tt_connected',username:'${username}'},'*');
          setTimeout(()=>window.close(), 1500);
        </script>
      </body></html>
    `);
  } catch (err) {
    console.error('OAuth error:', err.message);
    res.send(`<script>window.opener.postMessage({type:'tt_error',error:'${err.message}'},'*');window.close();</script>`);
  }
});

// ─────────────────────────────────────────────
// GET /auth/refresh
// Refreshes the access token using refresh_token
// ─────────────────────────────────────────────
app.post('/auth/refresh', async (req, res) => {
  const { clientKey, clientSecret } = getCreds();
  if (!tokenStore.refresh_token) return res.status(400).json({ error: 'No refresh token stored' });

  try {
    const r = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key:    clientKey,
        client_secret: clientSecret,
        grant_type:    'refresh_token',
        refresh_token: tokenStore.refresh_token,
      }),
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    saveToken({ ...tokenStore, access_token: data.access_token, expires_at: Date.now() + data.expires_in * 1000 });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// POST /auth/logout
// Clears stored token
// ─────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  tokenStore = {};
  try { fs.unlinkSync(TOKEN_FILE); } catch {}
  console.log('Logged out');
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// POST /upload/init
// Initialise a TikTok video upload
// ─────────────────────────────────────────────
app.post('/upload/init', async (req, res) => {
  if (!tokenStore.access_token) return res.status(401).json({ error: 'Not connected to TikTok' });

  const { post_info, source_info } = req.body;

  try {
    const r = await fetch('https://open.tiktokapis.com/v2/post/publish/video/init/', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + tokenStore.access_token,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({ post_info, source_info }),
    });
    const data = await r.json();
    if (data.error?.code && data.error.code !== 'ok') throw new Error(data.error.message || JSON.stringify(data.error));
    res.json(data);
  } catch (err) {
    console.error('Upload init error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /upload/status/:publishId
// Check the status of a published video
// ─────────────────────────────────────────────
app.get('/upload/status/:publishId', async (req, res) => {
  if (!tokenStore.access_token) return res.status(401).json({ error: 'Not connected' });

  try {
    const r = await fetch('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + tokenStore.access_token,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({ publish_id: req.params.publishId }),
    });
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// Start server
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('┌─────────────────────────────────────┐');
  console.log('│           TikPublish Server          │');
  console.log(`│   Running at http://localhost:${PORT}   │`);
  console.log('└─────────────────────────────────────┘');
  console.log('');
  if (!process.env.TIKTOK_CLIENT_KEY) {
    console.log('⚠  TIKTOK_CLIENT_KEY not set — edit .env before connecting');
  } else {
    console.log('✓  Credentials loaded from .env');
  }
  if (tokenStore.access_token) {
    console.log(`✓  Logged in as ${tokenStore.username || 'TikTok User'}`);
  }
  console.log('');
});
