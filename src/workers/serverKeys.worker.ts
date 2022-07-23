import keys from '../utils/keys';
const { workerData, parentPort } = require("worker_threads")


interface IncomingData{
  key?: string,
  pathToFile?: string,
  keyName?: string,
  password?: string,
  hashPassword?: string,
  rounds?: number,
  method?: string,
  data?: string | Buffer,
};

const {
  getSecret, 
  decryptWithPrivate,
  encryptWithPublic,
  createKeys,
  readKey,
  encryptPassword,
  confirmPassword
} = keys

const {  workType: string, data: IncomingData } = workerData

parentPort.postMessage({
  
})


//generate keys

//save keys

//get saved keys

//encrypt with public

//decrypt with private

//encrypt Password

//decrypt password

