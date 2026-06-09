// api/tuya.js — KeyVault Proxy by Edifio
// Version finale — signature + chiffrement AES du code PIN (requis par Tuya)

import crypto from 'crypto'

const CLIENT_ID     = process.env.TUYA_CLIENT_ID
const CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET
const BASE_URL      = 'https://openapi.tuyaeu.com'

// ── Cache token ──
let _token = null, _tokenExp = 0

// ── Helpers crypto ──
const hmacSha256 = (msg, secret) =>
  crypto.createHmac('sha256', secret).update(msg,'utf8').digest('hex').toUpperCase()

const sha256Hex = (str) =>
  crypto.createHash('sha256').update(str||'','utf8').digest('hex')

// ── Signature Tuya v1.0 (nouvelle version post-juin 2021) ──
// Token endpoint : str = clientId + t + stringToSign
// Autres endpoints : str = clientId + accessToken + t + stringToSign
// stringToSign = method\nSHA256(body)\n\npathWithQuery
function buildSign({ token='', t, method, path, bodyStr='' }) {
  const bodyHash = sha256Hex(bodyStr)
  const sts = [method.toUpperCase(), bodyHash, '', path].join('\n')
  return hmacSha256(CLIENT_ID + token + t + sts, CLIENT_SECRET)
}

// ── Token avec cache ──
async function getToken() {
  const now = Date.now()
  if (_token && now < _tokenExp) return _token
  const t = now.toString()
  const path = '/v1.0/token?grant_type=1'
  const sign = buildSign({ token:'', t, method:'GET', path, bodyStr:'' })
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { client_id:CLIENT_ID, sign, t, sign_method:'HMAC-SHA256' }
  })
  const d = await res.json()
  if (!d.success) throw new Error(`Auth: ${d.msg} [${d.code}]`)
  _token = d.result.access_token
  _tokenExp = now + (d.result.expire_time||7200)*1000 - 30000
  return _token
}

// ── Appel API Tuya signé ──
async function call({ method, path, body=null }) {
  const token = await getToken()
  const t = Date.now().toString()
  const bodyStr = body ? JSON.stringify(body) : ''
  const sign = buildSign({ token, t, method, path, bodyStr })
  const opts = {
    method,
    headers: {
      client_id:CLIENT_ID, access_token:token,
      sign, t, sign_method:'HMAC-SHA256',
      'Content-Type':'application/json'
    }
  }
  if (bodyStr && method!=='GET' && method!=='DELETE') opts.body = bodyStr
  const res = await fetch(BASE_URL + path, opts)
  const d = await res.json()
  if (!d.success) throw new Error(`Tuya ${method} ${path}: ${d.msg} [${d.code}]`)
  return d.result
}

// ── AES password encryption (requis par Tuya WiFi lock) ──
// 1. Obtenir ticket → ticket_key (AES-256-ECB chiffré avec clientSecret)
// 2. Déchiffrer ticket_key pour obtenir la clé AES → aes_key
// 3. Chiffrer le PIN avec AES-128-ECB-PKCS7 using aes_key → hex
async function encryptPassword(deviceId, plainPwd) {
  // Step 1: Obtenir le ticket
  const ticket = await call({
    method:'POST',
    path:`/v1.0/devices/${deviceId}/door-lock/password-ticket`
  })
  const { ticket_id, ticket_key } = ticket

  // Step 2: Déchiffrer ticket_key avec AES-256-ECB(clientSecret)
  // ticket_key est en hex, clientSecret utilisé directement comme clé (32 bytes)
  const secretBuf = Buffer.from(CLIENT_SECRET.slice(0,32), 'utf8') // 32 bytes pour AES-256
  const ticketBuf = Buffer.from(ticket_key, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-ecb', secretBuf, null)
  decipher.setAutoPadding(false)
  const aesKey = Buffer.concat([decipher.update(ticketBuf), decipher.final()])

  // Step 3: Chiffrer le PIN avec AES-128-ECB-PKCS7
  // AES-128 = 16 bytes key
  const aes128Key = aesKey.slice(0,16)
  const cipher = crypto.createCipheriv('aes-128-ecb', aes128Key, null)
  // PKCS7 padding est automatique avec createCipheriv
  const pwdBuf = Buffer.from(plainPwd, 'utf8')
  const encryptedPwd = Buffer.concat([cipher.update(pwdBuf), cipher.final()]).toString('hex')

  return { ticket_id, encrypted_password: encryptedPwd }
}

// ── Vercel config ──
export const config = { api: { bodyParser: { sizeLimit: '1mb' } } }

// ── Handler principal ──
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST')   return res.status(405).json({ error:'POST requis' })

  if (!CLIENT_ID || !CLIENT_SECRET)
    return res.status(500).json({ error:'TUYA_CLIENT_ID ou TUYA_CLIENT_SECRET manquant' })

  try {
    const { action, deviceId, pwdId, body:rb } = req.body || {}
    if (!action) return res.status(400).json({ error:'action requise' })

    // ── 1. Statut serrure ──
    if (action === 'getDevice') {
      if (!deviceId) return res.status(400).json({ error:'deviceId requis' })
      const r = await call({ method:'GET', path:`/v1.0/devices/${deviceId}` })
      return res.json({ success:true, result:r })
    }

    // ── 2. Créer code PIN temporaire ──
    // IMPORTANT: Tuya WiFi lock requiert le mot de passe AES-chiffré via ticket
    if (action === 'createCode') {
      const { name, password, effectiveTime, invalidTime } = rb || {}
      if (!deviceId||!password||!effectiveTime||!invalidTime)
        return res.status(400).json({ error:'deviceId, password, effectiveTime, invalidTime requis' })

      // Chiffrer le PIN
      const { ticket_id, encrypted_password } = await encryptPassword(deviceId, String(password))

      // Créer le mot de passe sur Tuya
      const r = await call({
        method:'POST',
        path:`/v1.0/devices/${deviceId}/door-lock/temp-password`,
        body:{
          Name: name || 'Locataire',   // capital N selon docs Tuya
          password: encrypted_password,
          effective_time: Math.floor(effectiveTime / 1000),
          invalid_time:   Math.floor(invalidTime   / 1000),
          password_type: 'ticket',
          ticket_id
        }
      })
      // Retourner l'ID Tuya + le PIN en clair (pour l'afficher au locataire)
      return res.json({ success:true, result:{ id:r?.id, password:String(password) } })
    }

    // ── 3. Révoquer code ──
    if (action === 'revokeCode') {
      if (!deviceId||!pwdId) return res.status(400).json({ error:'deviceId et pwdId requis' })
      await call({ method:'DELETE', path:`/v1.0/devices/${deviceId}/door-lock/temp-passwords/${pwdId}` })
      return res.json({ success:true })
    }

    // ── 4. Lock / Unlock distant ──
    if (action === 'remoteControl') {
      const { lockAction } = rb || {}
      if (!deviceId||!lockAction) return res.status(400).json({ error:'deviceId et lockAction requis' })
      await call({
        method:'POST',
        path:`/v1.0/devices/${deviceId}/commands`,
        body:{ commands:[{ code:'lock_motor_state', value: lockAction==='lock' }] }
      })
      return res.json({ success:true })
    }

    // ── 5. Statut batch serrures ──
    if (action === 'getLocks') {
      const { deviceIds } = rb || {}
      if (!Array.isArray(deviceIds)||deviceIds.length===0)
        return res.status(400).json({ error:'deviceIds array requis' })
      const results = await Promise.all(deviceIds.map(id =>
        call({ method:'GET', path:`/v1.0/devices/${id}` })
          .then(d => {
            const st  = d.status||[]
            const bat = st.find(x=>x.code==='battery_percentage')?.value ?? null
            const lk  = st.find(x=>x.code==='lock_motor_state')?.value
            return { deviceId:id, electricQuantity:bat, lockStatus:lk?1:0, online:d.online??false }
          })
          .catch(err => ({ deviceId:id, electricQuantity:null, lockStatus:0, online:false, error:err.message }))
      ))
      return res.json({ success:true, result:results })
    }

    return res.status(400).json({ error:`Action inconnue: ${action}` })

  } catch(err) {
    console.error('[KeyVault Proxy]', err.message)
    if (err.message.includes('1010')||err.message.includes('expire')) {
      _token=null; _tokenExp=0
    }
    return res.status(500).json({ error:err.message })
  }
}
