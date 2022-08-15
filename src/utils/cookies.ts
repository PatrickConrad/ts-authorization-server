import {Request} from 'express'

interface CookieOptions {
    expires: Date,
    secure: boolean,
    httpOnly: boolean,
    sameSite: 'Lax'|'None'|'Strict'
}

const setOptions = (exp: number ,type?: string ) => {
    try{
        const cookieOptions: CookieOptions = {
            expires: new Date(exp),
            secure: true,
            httpOnly: true,
            sameSite: 'Lax'
        }
        if(process.env.NODE_ENV==='development' && type === 'client'){
            cookieOptions.secure = true;
            cookieOptions.sameSite = 'None';
            cookieOptions.httpOnly = false;
            console.log({cookieOptions})
            return cookieOptions;
        }
        if(process.env.NODE_ENV==='development'){
            cookieOptions.secure = false;
            cookieOptions.sameSite = 'Lax';
            return cookieOptions;
        }

        //if type exists special handlers here 
        if(type === 'client'){
            cookieOptions.httpOnly = false;
            cookieOptions.sameSite = 'Lax';
            cookieOptions.secure = true
            return cookieOptions
        }
        //return default options if enviornment is not development or no special type handlers
        console.log({cooks: cookieOptions})
        return cookieOptions;
    }
    catch(error){
        return {}
    }
}


const getCookie = (req: Request, cookieName: string) => {
    if(req && req.headers.cookie){
        const stringCookies = req.headers.cookie.split(';')
        if(!cookieName) return stringCookies
        const hasCookie = stringCookies.find(c=> {
            return c.includes(cookieName)
        } )
        return !hasCookie ? false: hasCookie?.split('=')[1].replace(/%3D/g, '=').replace(/%2B/g, '+').replace(/%2F/g, '/');
    }
}   

const cookies = {
    getCookie,
    setOptions
}

export default cookies
