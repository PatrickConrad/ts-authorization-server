import crypto from 'crypto';
import {keys} from './keys';
import path from 'path';
import { ObjectId } from 'mongoose';

interface TokenType {
    key: string,
    passphrase: string,
    exp: string
}

const keyDir = path.join(__dirname, '../../serverKeys/privateKeys')
const tokenTypes = {
    access: {
        key: keys.readKey('AccessPrivateKey', keyDir),
        passphrase: process.env.ACCESS_TOKEN_PASSPHRASE as string,
        exp: process.env.ACCESS_TOKEN_EXPIRES as string,
    },
    refresh: {
        key: keys.readKey('RefreshPrivateKey', keyDir),
        passphrase: process.env.REFRESH_TOKEN_PASSPHRASE as string,
        exp: process.env.REFRESH_TOKEN_EXPIRES as string
    },
    email: {
        key: keys.readKey('EmailPrivateKey', keyDir),
        passphrase: process.env.EMAIL_TOKEN_PASSPHRASE as string,
        exp: process.env.EMAIL_TOKEN_EXPIRES as string
    },
    phone: {
        key: keys.readKey('PhonePrivateKey', keyDir),
        passphrase: process.env.PHONE_TOKEN_PASSPHRASE as string,
        exp: process.env.PHONE_TOKEN_EXPIRES as string
    },
    resetPw: {
        key: keys.readKey('ResetPwPrivateKey', keyDir),
        passphrase: process.env.RESET_PW_TOKEN_PASSPHRASE as string,
        exp: process.env.RESET_PW_TOKEN_EXPIRES as string
    },
    forgotPw: {
        key: keys.readKey('ForgotPwPrivateKey', keyDir),
        passphrase: process.env.FORGOT_ID_TOKEN_PASSPHRASE as string,
        exp: process.env.FORGOT_PW_TOKEN_EXPIRES as string
    },
    verify: {
        key: keys.readKey('VerifyPrivateKey', keyDir),
        passphrase: process.env.VERIFY_ACCOUNT_TOKEN_PASSPHRASE as string,
        exp: process.env.VERIFY_ACCOUNT_TOKEN_EXPIRES as string
    }
}

export interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: string,
    iss: string,
    tai: number | string
}


export interface SignJwt {
    type: 'access' | 'refresh' | 'email' | 'phone' | 'verify' | 'resetPw' | 'forgotPw', 
    id: string, 
    hostname: string, 
    alg?: string
}

const setJwtInfo = (type: string, userAlg?: string) =>{
    const alg = userAlg || 'RSA-SHA256';
    const tai = Date.now().toString();
    const iss = process.env.TOKEN_AUTHORITY;
    
}

const convertToString = (options: Options) => {
        const conversion = Buffer.from(JSON.stringify(options)).toString('base64');
        return conversion;
}
const convertFromString = (val: String) =>{
    const conversion = Buffer.from(val, 'base64').toString('ascii');
    return conversion;
}

const signToken = (jwt: SignJwt) => {
    const issuer = process.env.TOKEN_AUTHORITY as string
    const tokenData = tokenTypes[jwt.type]
    const dataString = Buffer.from(JSON.stringify({id: jwt.id}));
    const getAlg = jwt.alg?jwt.alg:'RSA-SHA256'
    const sig = crypto.sign(getAlg, dataString, {key: tokenData.key, passphrase: tokenData.passphrase}).toString('base64');
    const token = `${convertToString({alg: getAlg, exp: tokenData.exp, aud: jwt.hostname, sub: jwt.id, iss: issuer, tai: Date.now().toString()})}.${dataString}.${sig}`;
    return token;
}

const verifyToken = (token: string, key: string) => {
    const segments = (tkn: string) => {
        const segment = tkn.split('.');
        return {
            header: JSON.parse(convertFromString(segment[0])),
            payload: convertFromString(segment[1]),
            signature: Buffer.from(segment[2], 'base64')
        }
    }
    const {header, payload, signature} = segments(token);
    
    const verify = crypto.verify(header.alg, Buffer.from(payload), key, signature);
    return {isVerified: verify, expired: parseInt(header.tai)+parseInt(header.exp)<Date.now()?true:false, payload: JSON.parse(payload), header}
}

const jwts = {
    verifyToken,
    signToken
}

export default jwts;

//-----------Testing------------------

// const testData = {id: '123hi', roles: ['user', 'admin']}
// const testOptions = {exp: '5000', alg: 'RSA-SHA256', iss: 'mytest', sub: 'user', aud: 'mytest.com', tai: Date.now().toString()}
// const privateKey = readKey('refreshTokenPrivateKey')
// const publicKey = readKey('refreshTokenPublicKey')

// export const token = () => {
//     const t = signToken(privateKey, testData, testOptions);
//     console.log({t})
//     return t
// }
// export const info = (tkn: string) => {
//     const vt = verifyToken(tkn, publicKey);
//     return vt;
// }
