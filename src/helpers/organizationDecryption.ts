import {utils} from '../utils';
import path from 'path';
export const organizationDecryption = (org: any) => {
    try{
        const publicKey = utils.keys.readKey('OrganizationAuth', path.join(__dirname, '../../serverKeys', ))
        const encrypted = utils.keys.encryptWithPublic(publicKey, org);
        return encrypted;
    }
    catch(err: any){
        return {success: false}
    }
}