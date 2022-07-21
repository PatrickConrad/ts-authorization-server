import crypto from 'crypto';

interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: string,
    iss: string,
    tai: number | string
}

interface IdData {
    id: string, 
    roles?: Array<string>
}

const convertToString = (options: Options | IdData) => {
        const conversion = Buffer.from(JSON.stringify(options)).toString('base64');
        return conversion;
}
const converFromString = (val: String) =>{
    const conversion = Buffer.from(val, 'base64').toString('ascii');
    return conversion;
}

const signToken = (key: string, data: IdData, options : Options = {exp: '5000', tai: Date.now().toString(), alg: 'RSA-SHA256', iss: 'localhost'}) => {
    const dataString = Buffer.from(JSON.stringify(data));
    const sig = crypto.sign(options.alg, dataString, {key, passphrase: process.env.PRIVATE_KEY_SECRET}).toString('base64');
    const token = `${convertToString(options)}.${convertToString(data)}.${sig}`;
    return token;
}

const verifyToken = (token: string, key: string) => {
    const segments = (tkn: string) => {
        const segment = tkn.split('.');
        return {
            header: JSON.parse(converFromString(segment[0])),
            payload: converFromString(segment[1]),
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
