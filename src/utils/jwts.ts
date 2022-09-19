import crypto from 'crypto';
import {keys} from './keys';
import path from 'path';
import { ObjectId } from 'mongoose';

interface UserInfo {
    iss: string,
    azp: string,
    aud: string,
    sub: string,
    email: string,
    email_verified: string,
    at_hash: string,
    name: string,
    picture: string,
    given_name: string,
    family_name: string,
    locale: string,
    iat: number,
    exp: number
}

interface TokenType {
    key: string,
    passphrase: string,
    exp: string
}

interface VerifiedToken {
    isVerified: boolean,
    expired: boolean,
    payload: Payload | UserInfo,
    header: Options
}

export interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: ObjectId | string,
    iss: string,
    tai: number | string
}

export type KeyType = 'organization_verify' | 'access' | 'refresh' | 'email' | 'phone' | 'verify' | 'reset_password' | 'forgot_password' | 'login' | 'test_carrier' | 'organization_consent' | 'consent'

export interface SignJwt {
    type:  KeyType,
    id: ObjectId | string, 
    hostname: string, 
    username?: string
    ip?: string,
    alg?: string
}

export interface Payload {
    id: ObjectId | string
}

export interface ConsentOrgPayload {
    id: ObjectId | string,
    username?: string
}

const keyDir = path.join(__dirname, '../../serverKeys/privateKeys')

const convertToString = (options: Options | Payload) => {
        const conversion = Buffer.from(JSON.stringify(options)).toString('base64');
        return conversion;
}
const convertFromString = (val: String) =>{
    const conversion = Buffer.from(val, 'base64').toString('ascii');
    return conversion;
}

const formatType = (type: string) => {
    if(!type.includes('_')) return type;
    const names = type.split('_')
    const FileNames = names.map(n=>{
        n.charAt(0).toUpperCase()+n.slice(1)
    })
    const fileName = FileNames.join('')
    return fileName;
}

const signToken= (jwt: SignJwt) => {
    const issuer = process.env.TOKEN_AUTHORITY as string
    const {type, username, ip, id, hostname, alg} = jwt;
    const fileName = formatType(type);
    const tokenData = {
        key: keys.readKey(`${fileName}PrivateKey`, keyDir),
        passphrase: process.env[`${type.toUpperCase()}_TOKEN_PASSPHRASE`] as string,
        exp: process.env[`${type.toUpperCase()}_TOKEN_EXPIRES`] as string
    }
    const pl: ConsentOrgPayload = {
        id: jwt.id as ObjectId,
    }
    if(username) pl.username = username;
    const ds = convertToString(pl)
    const dataString = Buffer.from(JSON.stringify(pl));
    const getAlg = alg??'RSA-SHA256'
    const timeSet = Date.now()
    const sig = crypto.sign(getAlg, dataString, {key: tokenData.key, passphrase: tokenData.passphrase}).toString('base64');
    const tkn = `${convertToString({alg: getAlg, exp: tokenData.exp, aud: hostname, sub: ip??id as ObjectId, iss: issuer, tai: `${timeSet}`})}.${ds}.${sig}`;
    const token = encodeURIComponent(tkn);
    return {token, expires: parseInt(tokenData.exp)+timeSet}
}


const verifyToken = (token: string, type: string) => {
    // console.log({tokenUpdate: tkn})
    const segments = (tkn: string) => {
        const segment = tkn.split('.');
        return {
            header: JSON.parse(convertFromString(segment[0])),
            payload: segment[1],
            signature: Buffer.from(segment[2], 'base64')
        }
    }
    const t = decodeURIComponent(token);
    const {header, payload, signature} = segments(t);
    const fileName = formatType(type);
    if(fileName==='google'){
        const pl: UserInfo = JSON.parse(convertFromString(payload));
        const info: VerifiedToken = {isVerified: false, expired: Date.now()>pl.exp?true:false, payload: pl, header}
        return info;
    }
    
    const key = keys.readKey(`${fileName.charAt(0).toUpperCase() + fileName.slice(1)}PublicKey`, path.join(__dirname, "../../serverKeys/publicKeys"));
    const verify = crypto.verify(header.alg, Buffer.from(convertFromString(payload)), key, signature);
    const info: VerifiedToken = {isVerified: verify, expired: parseInt(header.tai)+parseInt(header.exp)<Date.now()?true:false, payload: JSON.parse(convertFromString(payload)), header}
    return info
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
