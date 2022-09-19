import { utils } from './../utils/index';
import { CacheContainer } from 'node-ts-cache'
import { MemoryStorage } from 'node-ts-cache-storage-memory'

const secretCache = new CacheContainer(new MemoryStorage())
const domainCache = new CacheContainer(new MemoryStorage())
interface ReturnCache {
    success: boolean,
    msg?: string,
    data?: string
}

const networkFailed = {
    success: false,
    msg: "network error"
}

export class AuthService {

    public async setConsent(id: string, domain: string): Promise<ReturnCache> {
        try{
            //id combines ip and other user info
            await secretCache.setItem(id, domain, {ttl: 300})
            console.log("working")
            return {success: true}    
        }
        catch(err){
            console.log({err})
            return networkFailed
        }
    }
    public async getConsent( id: string): Promise<ReturnCache> {
        try{
            const secret = await secretCache.getItem(id);
            console.log("working")

            if(!secret || secret === undefined) return {success: false, msg: 'not found'}
            return {success: true, data: `${secret}`}    
        }
        catch(err){
            console.log({err})
            return networkFailed
        }
    }
    public async setDomains(domain: string, orgId: string, styles?: string): Promise<ReturnCache> {
        try{
            const exp = 172800
            const exists = await domainCache.getItem<string>(domain);
            if(exists && exists.split('+=+')[0]!==orgId) return {success: false, msg: "orgId does not match id for existing domain"};
            await domainCache.setItem(domain, `${orgId}\+\=\+${styles??''}`, {ttl: exp})
            return {success: true}    
        }
        catch(err){
            console.log({err})
            return networkFailed
        }
    }
    public async getDomain<ReturnCache>(domain: string, orgId: string) {
        try{
            const d = await domainCache.getItem(domain);
            if(!d) return {success: false, msg: 'not found'}
            return {success: true} //check if domain has already been confirmed
        }
        catch(err){
            console.log({err})
            return networkFailed
        }
    }
}

export const memoryCache = new AuthService();