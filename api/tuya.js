// api/tuya.js — KeyVault Proxy by Edifio
// R-Lock DPs confirmed from logs:
// unlock_phone_remote = true (unlock remotely — boolean DP)
// lock_motor_state = true (locked), false (unlocked)
// residual_electricity = battery %
// temporary_password_creat / temporary_password_delete = temp codes

import crypto from 'crypto'

const CLIENT_ID     = process.env.TUYA_CLIENT_ID
const CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET
const BASE_URL      = 'https://openapi.tuyaeu.com'

let _token = null, _tokenExp = 0

const hmacSha256 = (msg, secret) =>
  crypto.createHmac('sha256', secret).update(msg,'utf8').digest('hex').toUpperCase()
const sha256Hex = (str) =>
  crypto.createHash('sha256').update(str||'','utf8').digest('hex')

function buildSign({ token='', t, method, path, bodyStr='' }) {
  const bodyHash = sha256Hex(bodyStr)
  const sts = [method.toUpperCase(), bodyHash, '', path].join('\n')
  return hmacSha256(CLIENT_ID + token + t + sts, CLIENT_SECRET)
}

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

async function tuyaCall({ method, path, body=null }) {
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

// Battery: R-Lock uses residual_electricity
function getBattery(st) {
  return (
    st.find(x => x.code === 'residual_electricity') ||
    st.find(x => x.code === 'battery_percentage') ||
    st.find(x => x.code === 'battery') ||
    st.find(x => x.code === 'va_battery')
  )?.value ?? null
}

// Lock status: R-Lock uses lock_motor_state (true=locked, false=unlocked)
function getLockStatus(st) {
  const dp = st.find(x => x.code === 'lock_motor_state')
  if (dp !== undefined) return dp.value ? 1 : 0
  return 0
}

// AES encryption for PIN codes
async function encryptPassword(deviceId, plainPwd) {
  const ticket = await tuyaCall({
    method:'POST',
    path:`/v1.0/devices/${deviceId}/door-lock/password-ticket`
  })
  const { ticket_id, ticket_key } = ticket
  const secretBuf = Buffer.from(CLIENT_SECRET.slice(0,32), 'utf8')
  const ticketBuf = Buffer.from(ticket_key, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-ecb', secretBuf, null)
  decipher.setAutoPadding(false)
  const aesKey = Buffer.concat([decipher.update(ticketBuf), decipher.final()])
  const aes128Key = aesKey.slice(0,16)
  const cipher = crypto.createCipheriv('aes-128-ecb', aes128Key, null)
  const encryptedPwd = Buffer.concat([
    cipher.update(Buffer.from(plainPwd,'utf8')),
    cipher.final()
  ]).toString('hex')
  return { ticket_id, encrypted_password: encryptedPwd }
}

export const config = { api: { bodyParser: { sizeLimit: '1mb' } } }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST')   return res.status(405).json({ error:'POST requis' })
  if (!CLIENT_ID || !CLIENT_SECRET)
    return res.status(500).json({ error:'Variables Tuya manquantes sur Vercel' })

  try {
    const { action, deviceId, pwdId, body:rb } = req.body || {}
    if (!action) return res.status(400).json({ error:'action requise' })

    // 1. Statut appareil
    if (action === 'getDevice') {
      if (!deviceId) return res.status(400).json({ error:'deviceId requis' })
      const r = await tuyaCall({ method:'GET', path:`/v1.0/devices/${deviceId}` })
      return res.json({ success:true, result:r })
    }

    // 1b. Diagnostic — retourne status + functions du device
    if (action === 'debugDevice') {
      if (!deviceId) return res.status(400).json({ error:'deviceId requis' })
      const [device, functions, status] = await Promise.all([
        tuyaCall({ method:'GET', path:`/v1.0/devices/${deviceId}` }),
        tuyaCall({ method:'GET', path:`/v1.0/devices/${deviceId}/functions` }).catch(e=>({_err:e.message})),
        tuyaCall({ method:'GET', path:`/v1.0/devices/${deviceId}/status` }).catch(e=>({_err:e.message})),
      ])
      return res.json({ success:true, result:{ device, functions, status } })
    }

    // 2. Créer code PIN temporaire
    if (action === 'createCode') {
      const { name, password, effectiveTime, invalidTime } = rb || {}
      if (!deviceId||!password||!effectiveTime||!invalidTime)
        return res.status(400).json({ error:'Paramètres manquants' })

      let result
      try {
        // Try AES path first (door locks)
        const { ticket_id, encrypted_password } = await encryptPassword(deviceId, String(password))
        result = await tuyaCall({
          method:'POST',
          path:`/v1.0/devices/${deviceId}/door-lock/temp-password`,
          body:{
            Name: name||'Locataire',
            password: encrypted_password,
            effective_time: Math.floor(effectiveTime/1000),
            invalid_time: Math.floor(invalidTime/1000),
            password_type:'ticket',
            ticket_id
          }
        })
      } catch(e) {
        // Fallback: plain password (keybox)
        console.log('[KeyVault] Trying plain password path:', e.message)
        result = await tuyaCall({
          method:'POST',
          path:`/v1.0/devices/${deviceId}/door-lock/temp-passwords`,
          body:{
            name: name||'Locataire',
            password: String(password),
            effective_time: Math.floor(effectiveTime/1000),
            invalid_time: Math.floor(invalidTime/1000),
            type: 0
          }
        })
      }
      return res.json({ success:true, result:{ id:result?.id, password:String(password) } })
    }

    // 3. Révoquer code
    if (action === 'revokeCode') {
      if (!deviceId||!pwdId) return res.status(400).json({ error:'deviceId et pwdId requis' })
      try {
        await tuyaCall({ method:'DELETE', path:`/v1.0/devices/${deviceId}/door-lock/temp-passwords/${pwdId}` })
      } catch(e) {
        await tuyaCall({ method:'DELETE', path:`/v1.0/devices/${deviceId}/door-lock/temp-password/${pwdId}` })
      }
      return res.json({ success:true })
    }

    // 4. Remote unlock — R-Lock uses unlock_phone_remote (confirmed from logs)
    if (action === 'remoteControl') {
      const { lockAction } = rb || {}
      if (!deviceId||!lockAction) return res.status(400).json({ error:'deviceId et lockAction requis' })

      if (lockAction === 'unlock') {
        const errors = []

        // Strategy 1: v2.0 shadow properties — unlock_phone_remote
        try {
          await tuyaCall({ method:'POST', path:`/v2.0/cloud/thing/${deviceId}/shadow/properties/issue`, body:{ properties:{ unlock_phone_remote:1 } } })
          console.log('[KeyVault] S1 OK: v2.0 shadow unlock_phone_remote')
          return res.json({ success:true })
        } catch(e){ errors.push('S1:'+e.message); console.log('[KeyVault] S1 fail:', e.message) }

        // Strategy 2: door-lock/remote-no-dp-key endpoint
        try {
          await tuyaCall({ method:'POST', path:`/v1.0/devices/${deviceId}/door-lock/remote-no-dp-key`, body:{} })
          console.log('[KeyVault] S2 OK: remote-no-dp-key endpoint')
          return res.json({ success:true })
        } catch(e){ errors.push('S2:'+e.message); console.log('[KeyVault] S2 fail:', e.message) }

        // Strategy 3: door-lock/remote-unlock-login
        try {
          await tuyaCall({ method:'POST', path:`/v1.0/devices/${deviceId}/door-lock/remote-unlock-login`, body:{} })
          console.log('[KeyVault] S3 OK: remote-unlock-login')
          return res.json({ success:true })
        } catch(e){ errors.push('S3:'+e.message); console.log('[KeyVault] S3 fail:', e.message) }

        // Strategy 4: manual_lock = false (writable Boolean DP)
        try {
          await tuyaCall({ method:'POST', path:`/v1.0/devices/${deviceId}/commands`, body:{ commands:[{ code:'manual_lock', value:false }] } })
          console.log('[KeyVault] S4 OK: manual_lock false')
          return res.json({ success:true })
        } catch(e){ errors.push('S4:'+e.message); console.log('[KeyVault] S4 fail:', e.message) }

        throw new Error('Toutes les stratégies ont échoué — ' + errors.join(' | '))
      } else {
        // K5 auto-locks after 4s (automatic_lock=true) — no manual lock command needed
        console.log('[KeyVault] K5 auto-locks — skipping manual lock command')
        return res.json({ success:true, note:'Auto-lock active' })
      }
      return res.json({ success:true })
    }

    // 5. Statut batch
    if (action === 'getLocks') {
      const { deviceIds } = rb || {}
      if (!Array.isArray(deviceIds)||deviceIds.length===0)
        return res.status(400).json({ error:'deviceIds requis' })
      const results = await Promise.all(deviceIds.map(id =>
        tuyaCall({ method:'GET', path:`/v1.0/devices/${id}` })
          .then(d => {
            const st = d.status||[]
            return {
              deviceId: id,
              electricQuantity: getBattery(st),
              lockStatus: getLockStatus(st),
              online: d.online??false
            }
          })
          .catch(err => ({
            deviceId:id,
            electricQuantity:null,
            lockStatus:0,
            online:false,
            error:err.message
          }))
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
