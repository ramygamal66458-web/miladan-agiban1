```javascript
/**
 * api/admin-data.js
 * بوابة العمليات الحساسة للوحة الأدمن
 *
 * الوظيفة:
 * 1) التحقق من Session Token الخاص بالأدمن.
 * 2) استقبال أوامر لوحة الأدمن.
 * 3) إرسال الأوامر إلى Google Apps Script.
 * 4) إعادة نتيجة Google Apps Script للوحة الأدمن.
 */

import crypto from 'crypto';


// ============================================================
// SESSION SETTINGS
// ============================================================

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;


// ============================================================
// VERIFY ADMIN SESSION TOKEN
// ============================================================

function verifyToken(token) {

  try {

    const rawToken =
      String(token || '').trim();

    if (!rawToken) {
      return false;
    }


    // Decode Base64
    const decoded =
      Buffer
        .from(rawToken, 'base64')
        .toString('utf8');


    // Make sure the token is valid/canonical Base64
    const normalizedToken =
      rawToken.replace(/=+$/, '');

    const canonicalToken =
      Buffer
        .from(decoded, 'utf8')
        .toString('base64')
        .replace(/=+$/, '');


    if (
      !normalizedToken ||
      normalizedToken !== canonicalToken
    ) {
      return false;
    }


    // Expected format:
    //
    // username:timestamp:signature
    //

    const parts =
      decoded.split(':');


    if (parts.length !== 3) {
      return false;
    }


    const [
      username,
      timestamp,
      signature
    ] = parts;


    if (!username || !timestamp || !signature) {
      return false;
    }


    // ========================================================
    // SESSION SECRET
    // ========================================================

    const secret =
      process.env.ADMIN_SESSION_SECRET;


    if (!secret) {
      console.error(
        'ADMIN_SESSION_SECRET is not configured.'
      );

      return false;
    }


    // ========================================================
    // CREATE EXPECTED SIGNATURE
    // ========================================================

    const payload =
      `${username}:${timestamp}`;


    const expectedSignature =
      crypto
        .createHmac(
          'sha256',
          secret
        )
        .update(payload)
        .digest('hex');


    // Signature length must match
    if (
      signature.length !==
      expectedSignature.length
    ) {
      return false;
    }


    // Convert signatures to buffers
    const signatureBuffer =
      Buffer.from(
        signature,
        'hex'
      );


    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        'hex'
      );


    if (
      signatureBuffer.length !==
      expectedBuffer.length
    ) {
      return false;
    }


    // Secure comparison
    if (
      !crypto.timingSafeEqual(
        signatureBuffer,
        expectedBuffer
      )
    ) {
      return false;
    }


    // ========================================================
    // CHECK USERNAME
    // ========================================================

    const expectedUsername =
      process.env.ADMIN_USERNAME;


    if (!expectedUsername) {

      console.error(
        'ADMIN_USERNAME is not configured.'
      );

      return false;

    }


    if (
      username !== expectedUsername
    ) {
      return false;
    }


    // ========================================================
    // CHECK SESSION AGE
    // ========================================================

    const timestampNumber =
      Number(timestamp);


    if (
      !Number.isFinite(
        timestampNumber
      )
    ) {
      return false;
    }


    const age =
      Date.now() -
      timestampNumber;


    if (
      age < 0 ||
      age > SESSION_TTL_MS
    ) {
      return false;
    }


    return true;

  } catch (error) {

    console.error(
      'verifyToken error:',
      error
    );

    return false;

  }

}


// ============================================================
// MAIN HANDLER
// ============================================================

export default async function handler(
  req,
  res
) {

  // ==========================================================
  // HEADERS
  // ==========================================================

  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );

  res.setHeader(
    'Pragma',
    'no-cache'
  );

  res.setHeader(
    'Expires',
    '0'
  );

  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'POST, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );


  // ==========================================================
  // OPTIONS / CORS
  // ==========================================================

  if (
    req.method === 'OPTIONS'
  ) {

    return res
      .status(200)
      .end();

  }


  // ==========================================================
  // ONLY POST ALLOWED
  // ==========================================================

  if (
    req.method !== 'POST'
  ) {

    return res
      .status(405)
      .json({
        status: 'error',
        message: 'Method not allowed'
      });

  }


  // ==========================================================
  // READ REQUEST BODY
  // ==========================================================

  let body =
    req.body || {};


  // Some Vercel configurations
  // may provide body as a string.

  if (
    typeof body === 'string'
  ) {

    try {

      body =
        JSON.parse(body);

    } catch {

      return res
        .status(400)
        .json({
          status: 'error',
          message: 'صيغة الطلب غير صحيحة.'
        });

    }

  }


  // ==========================================================
  // EXTRACT DATA
  // ==========================================================

  const {
    sessionToken,
    action,
    payload = {}
  } = body;


  // ==========================================================
  // CHECK ACTION
  // ==========================================================

  if (
    !action ||
    typeof action !== 'string'
  ) {

    return res
      .status(400)
      .json({
        status: 'error',
        message: 'لم يتم تحديد العملية المطلوبة.'
      });

  }


  // ==========================================================
  // VERIFY ADMIN SESSION
  // ==========================================================

  if (
    !verifyToken(sessionToken)
  ) {

    return res
      .status(401)
      .json({
        status: 'error',
        message:
          'جلسة الأدمن غير صالحة أو انتهت. سجل الدخول مرة أخرى.'
      });

  }


  // ==========================================================
  // GOOGLE APPS SCRIPT URL
  // ==========================================================

  const GAS_URL =
    String(
      process.env.GAS_URL || ''
    ).trim();


  if (!GAS_URL) {

    console.error(
      'GAS_URL environment variable is not configured.'
    );

    return res
      .status(503)
      .json({
        status: 'error',
        message:
          'GAS_URL غير مضبوط في Environment Variables في Vercel.'
      });

  }


  // ==========================================================
  // GOOGLE APPS SCRIPT TOKEN
  // ==========================================================

  const GAS_TOKEN =
    String(
      process.env.GAS_TOKEN || ''
    ).trim();


  if (!GAS_TOKEN) {

    console.error(
      'GAS_TOKEN environment variable is not configured.'
    );

    return res
      .status(503)
      .json({
        status: 'error',
        message:
          'GAS_TOKEN غير مضبوط في Environment Variables في Vercel.'
      });

  }


  // ==========================================================
  // PREPARE GOOGLE APPS SCRIPT REQUEST
  // ==========================================================

  const gasBody = {

    ...(payload &&
      typeof payload === 'object'
      ? payload
      : {}),

    action,

    token:
      GAS_TOKEN

  };


  // ==========================================================
  // CALL GOOGLE APPS SCRIPT
  // ==========================================================

  try {

    const response =
      await fetch(
        GAS_URL,
        {
          method: 'POST',

          headers: {
            'Content-Type':
              'application/json',

            'Accept':
              'application/json'
          },

          body:
            JSON.stringify(
              gasBody
            ),

          redirect:
            'follow'
        }
      );


    // ========================================================
    // READ RESPONSE
    // ========================================================

    const text =
      await response.text();


    if (!text) {

      return res
        .status(502)
        .json({
          status: 'error',
          message:
            'Google Apps Script رجع استجابة فارغة.'
        });

    }


    // ========================================================
    // PARSE JSON
    // ========================================================

    let result;

    try {

      result =
        JSON.parse(text);

    } catch (error) {

      console.error(
        'Invalid Google Apps Script response:',
        text
      );

      return res
        .status(502)
        .json({
          status: 'error',
          message:
            'Google Apps Script لم يرجع JSON صالح.',
          details:
            text.slice(0, 500)
        });

    }


    // ========================================================
    // FORWARD RESPONSE
    // ========================================================

    if (!response.ok) {

      return res
        .status(502)
        .json({

          status:
            result.status ||
            'error',

          message:
            result.message ||
            `Google Apps Script HTTP ${response.status}`,

          data:
            result.data ??
            null

        });

    }


    return res
      .status(200)
      .json(result);


  } catch (error) {

    console.error(
      'Google Apps Script request error:',
      error
    );


    return res
      .status(502)
      .json({
        status: 'error',
        message:
          'تعذر الاتصال بـ Google Apps Script.',
        details:
          error.message
      });

  }

}
```
