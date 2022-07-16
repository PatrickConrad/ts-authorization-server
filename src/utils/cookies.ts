import {Request} from 'express'
interface Obj {
    name: string,
    cookie: string
}
type ObjectKey = keyof typeof Object;

export const cookieExtractor = async (setCookies: string) => {
    
    let cookies: Obj | {} = {};
    
    const stringCookies = setCookies.split(';')
    console.log({stringCookies: stringCookies.length})
    if(stringCookies.length >=1){
        const cooks = ()=> stringCookies.map((c: string)=>{
            return {
                name: c.split('=')[0], 
                cookie: c.split('=')[1]
            }
        })
        cookies = await cooks()
    }
    console.log({adfafjkacookies: cookies})
    return cookies
}


export const getCookie = (req: Request, cookieName: string) => {
    if(req && req.headers.cookie){
        const stringCookies = req.headers.cookie.split(';')
        const hasCookie = stringCookies.find(c=> {
            if(c.includes(cookieName)){
                return cookieName.split('=')[1]
            }
            return null
        } )
    }
}   
// test
// "test=123"