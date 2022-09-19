import { IUser } from './../interfaces/register.d';
import {utils} from '../utils';
import path from 'path';
import { Nxt, Req, Res } from '../interfaces/types';
export const organization = {
    organizationDecryption: (org: any) => {
        try{
            const publicKey = utils.keys.readKey('OrganizationAuth', path.join(__dirname, '../../serverKeys', ))
            const encrypted = utils.keys.encryptWithPublic(publicKey, org);
            return encrypted;
        }
        catch(err: any){
            return {success: false}
        }
    },
    orgLogin: (req: Req, res: Res, next: Nxt) =>{ 
        const orgAuthReqData: {user: IUser, redirect: string} = req.body.midware.orgAuth;
        const {user, redirect} = orgAuthReqData;
        const userData = {
            id: user._id,
            phoneVerified: user.phoneVerified,
            emailVerified: user.emailVerified
        }
        const orgKey = utils.keys.readKey('OrganizationAuthPublicKey', path.join(__dirname, '../../serverKeys/publicKeys'))
        console.log({orgKey})
        const encrypted = encodeURIComponent(utils.keys.encryptWithPublic(orgKey, JSON.stringify(userData)));
        console.log({encrypted})
        const code = new URLSearchParams({code: encrypted})
        console.log({code})
        const clientUrl = `${redirect}?${code}`
        return res.status(200).json({
            success: true,
            clientUrl
        })
    }
}