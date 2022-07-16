import fs from 'fs';
import path from 'path';

const type = (fileName: string) => fileName.toLowerCase().includes('private') ? 'privateKeys' : 'publicKeys'


export const readKey = (fileName: string, pathToFile = path.join(__dirname, `../../serverKeys`)) => {
    const key = fs.readFileSync(`${pathToFile}/${type(fileName)}/${fileName}.pem`, 'utf8')

    return key;
  }