import crypto from 'crypto';
import jwt from 'jsonwebtoken';

export function base64URLEncode(str) {
  return str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export function sha256(buffer) {
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest();
}

export function validateIDToken(idToken, state, issuer) {
  console.log('chegou aqui 5');
  const decodedToken = jwt.decode(idToken);
  console.log(`decodedToken: ${JSON.stringify(decodedToken)}`);
  // fetch ID token details
  const {
    state: decodedState,
    // aud: audience,
    exp: expirationDate,
    iss: issuerDecoded
  } = decodedToken;
  const currentTime = Math.floor(Date.now() / 1000);
  // const expectedAudience = CLIENT_ID;

  // validate ID tokens
  if (
    // audience !== expectedAudience ||
    decodedState !== state ||
    expirationDate < currentTime ||
    issuerDecoded !== issuer
  )
    throw Error();

  // return the decoded token
  return decodedToken;
}
