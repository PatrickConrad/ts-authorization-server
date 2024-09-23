import axios from 'axios';
import qs from 'qs'

interface Code {
    code: string
}

interface Tokens {
    id_token: string,
    access_token: string
}

interface GoogleTokenResult {
    access_token: string,
    refresh_token: string,
    expires_in: number,
    scope: string,
    id_token: string
}

interface ResTokens {
    success: boolean,
    res: {
        id_token: string,
        access_token: string
    }
}

interface ResData {
    success: boolean,
    res: string
}

export const google = {
    getGoogleAuthUrl: () => {
        const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
    
        const options = {
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL as string,
            client_id: process.env.GOOGLE_CLIENT_ID as string,
            access_type: "offline",
            response_type: 'code',
            prompt: "consent",
            scope: [
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email"
            ].join(" ")
        }
    
        console.log("URL to google: ", `${rootUrl}?${qs.stringify(options)}`);
        return `${rootUrl}?${qs.stringify(options)}`
    },
    getGoogleTokens: async ({code}: {code: string}): Promise<ResTokens | ResData> => {
        try{
            const url = 'https://oauth2.googleapis.com/token';
            const values = {
                code,
                client_id: process.env.GOOGLE_CLIENT_ID as string,
                client_secret: process.env.GOOGLE_CLIENT_SECRET as string,
                redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL as string,
                grant_type: "authorization_code"
            }
            const resp = await axios.post(url, qs.stringify(values), {
                headers: {
                    'Content-Type': `application/x-www-form-urlencoded`,
                }
            })
            if(!resp){
                const error: ResData ={ success: false, res: 'No response recieved'}
                return error
            }
            const data: GoogleTokenResult = resp.data
            const tokens: ResTokens = {success: true, res: {id_token: data.id_token, access_token: resp.data.access_token}};
            return tokens
        }
        catch(err){
            const error: ResData = {success: false, res: "Internal Error"}
            return error

        }
    },
    getGoogleUser: async (tokens: Tokens) => {
        try{

            const url =`https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${tokens.access_token}`
            const resp = await axios.post(url, {
                headers: {
                    'Authorization': `Bearer ${tokens.id_token}`
                }
            })
            if(!resp){
                const error: ResData ={ success: false, res: 'No response recieved'}
                return error
            }
            console.log("response from google user: ", resp);
            // return {success: true, res: req}
            
        }
        catch(err){
            const error: ResData = {success: false, res: "Internal Error"}
            return error

        }
    }
}

