/* api/admin-data.js
 * بوابة العمليات الحساسة للوحة الأدمن
 */

import crypto from 'crypto';

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function verifyToken(token) {
  try {
    const raw = String(token || '');

    if (!raw) return false;

    const decoded = Buffer.from(raw, 'base64').toString('utf8');

    const normalizedToken = raw.replace(/=+$/, '');
    const canonicalToken = Buffer
      .from(decoded, 'utf8')
      .toString('base64')
      .replace(/=+$/, '');

    if (!normalizedToken || normalizedToken !== canonicalToken) {
      return false;
    }

    const parts = decoded.split(':');

    if (parts.length !== 3) {
      return false;
    }

    const [username, timestamp, signature] = parts;

    const secret = process.env.ADMIN_SESSION_SECRET;

    if (!secret) {
      return false;
    }

    const payload = `${username}:${timestamp}`;

    const expected = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    if (
      signature.length !== expected.length ||
      !/^[0-9a-f]+$/i.test(signature)
    ) {
      return false;
    }

    const signatureBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');

    if (
      signatureBuffer.length !== expectedBuffer.length ||
      signatureBuffer.length === 0
    ) {
      return false;
    }

    if (!crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
      return false;
    }

    const age = Date.now() - Number(timestamp);

    return (
      username === process.env.ADMIN_USERNAME &&
      Number.isFinite(age) &&
      age >= 0 &&
      age <= SESSION_TTL_MS
    );

  } catch (error) {
    console.error('verifyToken error:', error);
    return false;
  }
}

export default async function handler(req, res) {

  res.setHeader('Cache-Control', 'no-store, no-cache');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'POST, OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      status: 'error',
      message: 'Method not allowed'
    });
  }

  try {

    // ─────────────────────────────────────────────
    // Environment Variables
    // ─────────────────────────────────────────────

    const GAS_URL = String(
      process.env.GAS_URL || ''
    ).trim();

    const GAS_TOKEN = String(
      process.env.GAS_TOKEN || ''
    ).trim();

    if (!GAS_URL) {
      return res.status(503).json({
        status: 'error',
        message:
          'GAS_URL غير موجود في Vercel Environment Variables.'
      });
    }

    if (!GAS_TOKEN) {
      return res.status(503).json({
        status: 'error',
        message:
          'GAS_TOKEN غير موجود في Vercel Environment Variables.'
      });
    }

    // ─────────────────────────────────────────────
    // Request Body
    // ─────────────────────────────────────────────

    const body = req.body || {};

    const sessionToken = String(
      body.sessionToken || ''
    ).trim();

    const action = String(
      body.action || ''
    ).trim();

    const payload =
      body.payload &&
      typeof body.payload === 'object'
        ? body.payload
        : {};

    if (!sessionToken) {
      return res.status(401).json({
        status: 'error',
        message: 'جلسة الأدمن غير موجودة.'
      });
    }

    if (!verifyToken(sessionToken)) {
      return res.status(401).json({
        status: 'error',
        message: 'جلسة الأدمن غير صالحة أو انتهت.'
      });
    }

    if (!action) {
      return res.status(400).json({
        status: 'error',
        message: 'لم يتم تحديد العملية المطلوبة.'
      });
    }

    // ─────────────────────────────────────────────
    // Send to Google Apps Script
    // ─────────────────────────────────────────────

    const gasBody = {
      ...payload,
      action: action,
      token: GAS_TOKEN
    };

    const gasResponse = await fetch(GAS_URL, {
      method: 'POST',

      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },

      body: JSON.stringify(gasBody),

      redirect: 'follow'
    });

    const text = await gasResponse.text();

    // ─────────────────────────────────────────────
    // Parse GAS response safely
    // ─────────────────────────────────────────────

    let data = null;

    try {
      data = JSON.parse(text);
    } catch (parseError) {

      console.error(
        'Google Apps Script returned invalid JSON:',
        text
      );

      return res.status(502).json({
        status: 'error',

        message:
          'Google Apps Script لم يرجع JSON صالحًا.',

        httpStatus: gasResponse.status,

        details:
          text
            .replace(/\s+/g, ' ')
            .trim()
            .slice(0, 1000)
      });
    }

    // ─────────────────────────────────────────────
    // Return GAS response
    // ─────────────────────────────────────────────

    return res
      .status(gasResponse.ok ? 200 : 502)
      .json(data);

  } catch (error) {

    console.error(
      'admin-data fatal error:',
      error
    );

    return res.status(500).json({
      status: 'error',
      message:
        error?.message ||
        'حدث خطأ غير معروف في خادم الأدمن.'
    });
  }
}
