import {Request} from 'express'
interface Obj {
    name: string,
    cookie: string
}
const cookieExtractor = (setCookies: string) => {
    let cookies: Obj | {} = {};
    const stringCookies = setCookies.split(';')
    if(stringCookies.length >=1){
        const cooks = ()=> stringCookies.map((c: string)=>{
            return {
                name: c.split('=')[0], 
                cookie: c.split('=')[1]
            }
        })
        cookies = cooks()
    }
    return cookies
}


const getCookie = (req: Request, cookieName: string) => {
    if(req && req.headers.cookie){
        const stringCookies = req.headers.cookie.split(';')
        const hasCookie = stringCookies.find(c=> {
            if(c.includes(cookieName)){
                return cookieName.split('=')[1]
            }
            return false
        } )
        return hasCookie;
    }
}   

const cookies = {
    getCookie,
    cookieExtractor
}

export default cookies
