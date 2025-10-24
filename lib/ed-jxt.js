import vc from '@digitalbazaar/vc';

import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'

import { documentLoader } from './documentLoader'

import JXT from "jsonxt";

/**
 * 
 * @param {*} certificate 
 * @param {*} keyPairSerialized 
 * @param {*} publicPlainObject the public key may be null
 * @returns 
 */
export async function sign(certificate, keyPairSerialized, publicPlainObject=null) {
    const keyPair = await Ed25519VerificationKey2020.from(keyPairSerialized);
    const suite = new Ed25519Signature2020({key: keyPair});

    const credential = {
        ...certificate
    };

    return await vc.issue({credential, suite, documentLoader: (url) => documentLoader(url, publicPlainObject)});
}

/**
 * Verify a credential
 * @param {*} credential 
 * @param {*} publicPlainObject the public json object
 * @returns 
 */
export async function verify(credential, publicPlainObject=null) {
    const suite = new Ed25519Signature2020();

    const controller = {
        '@context': 'https://w3id.org/security/v3-unstable',
        id: credential.issuer,
        assertionMethod: [credential.proof.verificationMethod],
        authentication: [credential.proof.verificationMethod]
    };

    const verification = await vc.verifyCredential({
        credential,
        controller, 
        suite, 
        documentLoader: (url) => documentLoader(url, publicPlainObject)
    });
    //return verification.verified;
    return verification;
}

export async function unpack(uri, fullTemplate) {
  if (fullTemplate) 
    return await JXT.unpack(uri, ()=>{return fullTemplate;});
  else
    return await JXT.unpack(uri, JXT.resolveCache);
}    

export async function pack(signedData, domain, templateName, templateVersion, fullTemplate) {
  if (fullTemplate) 
    return await JXT.pack(signedData, fullTemplate, templateName, templateVersion, domain, {
        uppercase: true,
    });
  else
    return await JXT.resolvePack(signedData, templateName, templateVersion, domain, JXT.resolveCache, {
        uppercase: true,
    });
}

/**
 * 
 * @param {*} payload 
 * @param {*} keyPairSerialized 
 * @param {*} domain 
 * @param {*} templateName 
 * @param {*} templateVersion 
 * @param {*} publicPlainObject the public key in json format. May be null
 * @returns 
 */
export async function signAndPack(payload, keyPairSerialized, domain, templateName, templateVersion, publicPlainObject=null) {
  return await pack(await sign(payload, keyPairSerialized, publicPlainObject), domain, templateName, templateVersion);
}

export async function unpackAndVerify(uri, fullTemplate, publicPlainObject=null) {
  try {
    const json = await unpack(uri);
    if (await verify(json, publicPlainObject)) {
      return json;
    }
    return undefined;
  } catch (err) {
    console.log(err);
    return undefined;
  }
}
