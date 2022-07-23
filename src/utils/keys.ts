import fs from 'fs';
import path from 'path';
import crypto, {generateKeyPairSync, publicEncrypt, privateDecrypt} from 'crypto';

const getSecret = () => {
  return crypto.randomBytes(32).toString('hex')
}

const typeOfKey = (keyName: string) => keyName.toLowerCase().includes('private') ? 'privateKeys' : 'publicKeys'


const checkPath = async (dir: string, keyName:string, setPath: string): Promise<boolean> => {
  let doesExist = false;
  const reqPath = path.join(dir, setPath+typeOfKey(keyName))
  await fs.access(reqPath, (error) =>{
    if (error) {
      doesExist = false
      return 
    } else {
      doesExist = true
      return
    }

  })
  return doesExist
}

const saveKey = (key: string, keyName: string, pathToFile?: string) => {
  const setName = keyName+typeOfKey(keyName).toUpperCase()
  let setPath = pathToFile;
  if(!pathToFile) {
    setPath = `../config/keys/${typeOfKey(keyName)}`
  }
  fs.writeFileSync(`${pathToFile}/${typeOfKey(setName)}/${setName}.pem`, key);
}

const readKey = (keyName: string, pathToFile = path.join(__dirname, `../../serverKeys`)) => {
    const key = fs.readFileSync(`${pathToFile}/${typeOfKey(keyName)}/${keyName}.pem`, 'utf8')

    return key;
}

  
const createKeys = async (password: string, keyName: string, pathToFile?: string, method?: string) => {
  if(!password) return;
  const myKeys = generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: password
      }
    })
    const keys = myKeys
    const pathExists = await checkPath(__dirname, keyName,  !pathToFile?'':pathToFile)
    
    if(method === 'save'){
      if(!pathExists){
        fs.promises.mkdir(path.join(__dirname, pathToFile?pathToFile:''), { recursive: true });
      }
      saveKey(keys.privateKey, keyName);
      saveKey(keys.publicKey, keyName);  
      return;
    }
    return keys
    
  };

const  generateSalt = (rounds: number) => {
    if (rounds >= 15) {
        throw new Error(`${rounds} is greater than 15,Must be less that 15`);
    }
    if (typeof rounds !== 'number') {
        throw new Error('rounds param must be a number');
    }
    if (rounds == null) {
        rounds = 12;
    }
    return crypto.randomBytes(Math.ceil(rounds / 2)).toString('hex').slice(0, rounds);
};

const hasher = (password: string, salt: string) => {
    const hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    const value: string = hash.digest('hex');
    return value
};

const encryptPassword = (password: string, rounds?: number) => {
    let rds = !rounds ? 12 : rounds
    const salt: string = generateSalt(rds);
    console.log("SALT: ", salt.length);
    const hash: string = hasher(password, salt);
    const hashedPassword: string = `$${'1a'}$${rds}$${salt}${hash}`
    return hashedPassword
}

const confirmPassword = (password: string, hashedPassword: string) => {
    const parts = hashedPassword.split('$');
    const rounds = parts[1];
    const salt = parts[3].slice(parseInt(rounds));
    const hash = parts[3].slice(parseInt(rounds)+1, parts[3].length-1);
    console.log(salt);
    console.log(hash);
    const testPass = hasher(password, salt);
    if(testPass === hash) return console.log('True');
    return console.log('False')
}

const encryptWithPublic = (key: string, data: string)=> {
  const encryptBuffer = Buffer.from(data);
  const enc =  publicEncrypt(key , encryptBuffer)
  console.log("Text to be encrypted:");
  console.log(data);
  console.log("cipherText:");
  console.log(enc.toString());
  return enc.toString()
};

const decryptWithPrivate = (key: string, data: Buffer) => {
  const decryptBuffer = Buffer.from(data.toString("base64"), "base64");
  const decrypted = privateDecrypt(key, decryptBuffer);

  //print out the decrypted text
  console.log("decripted Text:");
  console.log(decrypted.toString());

  return decrypted; 
}

const createDiffie = (curve: string) => {
  const diffie = crypto.createECDH(curve)
  const keys = diffie.generateKeys();
  return { keys, diffie}
}

const getPublicDiffie = (diffie: crypto.ECDH) => {
  return diffie.getPublicKey();
}

const getSharedSecret = (diffie: crypto.ECDH, otherPublicKey: Buffer) => {
  return diffie.computeSecret(otherPublicKey).toString('base64');
}


const keys = {
  createDiffie,
  getPublicDiffie,
  getSharedSecret,
  decryptWithPrivate,
  encryptWithPublic,
  createKeys,
  readKey,
  encryptPassword,
  confirmPassword,
  getSecret
}
export default keys