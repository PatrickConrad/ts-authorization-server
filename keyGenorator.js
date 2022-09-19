const fs = require('fs');
const path = require('path');
const {generateKeyPairSync} = require('crypto');
const checkPath = async (setPath, pathType) => {
    let doesExist = false;
    const usePath = pathType?`/${pathType}Keys`:''
    const reqPath = setPath+usePath
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

const saveKey = (key, keyName, pathToFile, type) => {
    const setName = keyName.charAt(0).toUpperCase()+keyName.slice(1)+`${type?type.charAt(0).toUpperCase() + type.slice(1):''}`+'Key'
    return fs.writeFileSync(`${pathToFile}/${type}Keys/${setName}.pem`, key);
  }

const createKeys = async (password, keyName, pathToFile, method) => {
    if(!password) return;
    const usePath = pathToFile?pathToFile:path.join(__dirname, './serverKeys')
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
      const privatePathExists = await checkPath(usePath, 'private')
      const publicPathExists = await checkPath(usePath, 'public')
      
      if(method === 'save'){
        if(!privatePathExists){
          await fs.promises.mkdir(usePath+'/privateKeys', { recursive: true });
        }
        if(!publicPathExists){
        await fs.promises.mkdir(usePath+'/publicKeys', { recursive: true });
        }

        saveKey(keys.privateKey, keyName, usePath, 'private');
        saveKey(keys.publicKey, keyName, usePath, 'public');  
        return;
      }

      return keys
      
  }

  createKeys('d4703edec501fda9e27a817f3561854474c7160416811ab66f6619817ffafed6', 'organizationVerify', './serverKeys', 'save')