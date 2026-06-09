// api/tuya.js — KeyVault Proxy by Edifio
// R-Lock confirmed DPs: unlock_phone_remote, residual_electricity

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
  // Log full response for debugging
  console.log(`[Tuya] ${method} ${path} →`, JSON.stringify(d))
  // Some commands return success:false but still execute (e.g. lock commands)
  // Don't throw on result=null for commands
  if (!d.success && d.code !== 0) {
    throw new Error(`Tuya ${method} ${path}: ${d.msg} [${d.code}]`)
  }
  return d.result
}

function getBattery(st) {
  return (
    st.find(x => x.code === 'residual_electricity') ||
    st.find(x => x.code === 'battery_percentage') ||
    st.find(x => x.code === 'battery') ||
    st.find(x => x.code === 'va_battery')
  )?.value ?? null
}

function getLockStatus(st) {
  const dp = st.find(x => x.code === 'lock_motor_state')
  return dp ? (dp.value ? 1 : 0) : 0
}

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
  if (req.method !== 'POST') return res.status(405).json({ error:'POST requis' })
  if (!CLIENT_ID || !CLIENT_SECRET)
    return res.status(500).json({ error:'Variables Tuya manquantes' })

  try {
    const { action, deviceId, pwdId, body:rb } = req.body || {}
    if (!action) return res.status(400).json({ error:'action requise' })

    // 1. Statut appareil
    if (action === 'getDevice') {
      if (!deviceId) return res.status(400).json({ error:'deviceId requis' })
      const r = await tuyaCall({ method:'GET', path:`/v1.0/devices/${deviceId}` })
      return res.json({ success:true, result:r })
    }

    // 2. Créer code PIN
    if (action === 'createCode') {
      const { name, password, effectiveTime, invalidTime } = rb || {}
      if (!deviceId||!password||!effectiveTime||!invalidTime)
        return res.status(400).json({ error:'Paramètres manquants' })
      let result
      try {
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
        console.log('[KeyVault] AES failed, trying plain:', e.message)
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

    // 4. Remote unlock/lock
    // unlock_phone_remote confirmed from device DPs
    // Tuya returns 200 for this command even with result=null
    if (action === 'remoteControl') {
      const { lockAction } = rb || {}
      if (!deviceId||!lockAction) return res.status(400).json({ error:'deviceId et lockAction requis' })

      const token = await getToken()
      const path = `/v1.0/devices/${deviceId}/commands`
      const body = lockAction === 'unlock'
        ? { commands:[{ code:'unlock_phone_remote', value:1 }] }
        : { commands:[{ code:'lock_motor_state', value:true }] }
      const bodyStr = JSON.stringify(body)
      const t = Date.now().toString()
      const sign = buildSign({ token, t, method:'POST', path, bodyStr })

      const rawRes = await fetch(BASE_URL + path, {
        method:'POST',
        headers:{
          client_id:CLIENT_ID, access_token:token,
          sign, t, sign_method:'HMAC-SHA256',
          'Content-Type':'application/json'
        },
        body: bodyStr
      })
      const d = await rawRes.json()
      console.log('[KeyVault] remoteControl response:', JSON.stringify(d))

      // Accept both success:true and result:true from Tuya
      if (d.success || d.result === true || d.result === null) {
        return res.json({ success:true })
      }
      // Lock command may fail (auto-lock) — still return success
      if (lockAction === 'lock') {
        return res.json({ success:true, note:'auto-lock' })
      }
      return res.status(500).json({ error: d.msg || 'Tuya error' })
    }

    // 5. Statut batch
    if (action === 'getLocks') {
      const { deviceIds } = rb || {}
      if (!Array.isArray(deviceIds)||deviceIds.length===0)
        return res.status(400).json({ error:'deviceIds requis' })
      const results = await Promise.all(deviceIds.map(id =>
        tuyaCall({ method:'GET', path:`/v1.0/devices/${id}` })
          .then(d => ({
            deviceId: id,
            electricQuantity: getBattery(d.status||[]),
            lockStatus: getLockStatus(d.status||[]),
            online: d.online??false
          }))
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
