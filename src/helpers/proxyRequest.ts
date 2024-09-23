// import { models } from './../models/index';
// import { utils } from './../utils/index';
// import { Request, Response, NextFunction } from 'express';
// import http from 'http';
// import proxy from 'express-http-proxy';
// import qs from 'qs';
// import ErrorResponse from '../utils/errorResponse';
// import path from 'path'
// import { VerifiedToken } from './../types/imports';

// interface Options {
//     method: string,
//     headers: http.IncomingHttpHeaders,    
//     host: string,
//     port: string | number,
//     path: string
// }

// export const proxyRequest = async (options: Options, req: Request, res: Response) => {
//     const data: any = []
//     console.log("options")

//     const externalRequest = await http.request(options, (externalResponse)=>{
//         console.log("working")
//         res.writeHead(externalResponse.statusCode?externalResponse.statusCode:500, externalResponse.headers)
//         externalResponse.on("data", (chunk)=>{
//             console.log({headers: externalResponse.headers});
//             data.push(chunk)
//             res.write(chunk)
//         })

//         externalResponse.on("end", ()=>{
//             console.log({externalResponse})
//             return;
//         })
//     })
//     console.log(data)
//     return await externalRequest;
// }

// export const useProxy = async (req: Request, res: Response, next: NextFunction) => {
//     try{
//         const user = req.body.user;
//         const orgId = req.query.id as string;
//         const redirect = req.query.redirect as string;
//         if(!redirect) return next(new ErrorResponse("Must include a authorized redirect url", 400))
//         const exists = await models.User.findOne({email: user.identifier}).select("+password") || await models.User.findOne({phoneNumber: user.identifier}).select("+password") || await models.User.findOne({username: user.identifier}).select("+password")
//         if(!exists) return next(new ErrorResponse("User doesn't exist", 404))
//         const orgExists = await exists?.consents.find(c=> orgId===c)
//         if(!user.consent && !orgExists) return next(new ErrorResponse("Consent is requried for sign up", 404))
//         const hasAccess = await utils.cookies.getCookie(req, 'access') as string;
//         if(!hasAccess){
//             const match = utils.keys.confirmPassword(user.password, exists.password);
//             if(!match) return next(new ErrorResponse("User doesn't exist", 404))
//             if(!orgExists){
//                 exists.consents = [...exists.consents, orgId]
//                 await exists.save()
//             }
//             const data = {
//                 id: exists._id,
//                 phoneVerified: exists.phoneVerified,
//                 emailVerified: exists.emailVerified
//             }
//             const orgKey = utils.keys.readKey('OrganizationAuthPublicKey', path.join(__dirname, '../../serverKeys/publicKeys'))
//             const encrypted = utils.keys.encryptWithPublic(orgKey, JSON.stringify(data));
//             console.log({encrypted})
//             console.log("router", req.query)
//             console.log("redirect", req.query.redirect)
//             return res.send(proxy(`${redirect}?${qs.stringify({code: encrypted})}`))
//             // const clientUrl = `${redirect}?${qs.stringify({code: encrypted})}`
//             // // const resp = await axios.post(clientUrl)
//             // // console.log(resp.request.socket._httpMessage._redirectable._currentRequest.res)
//             // // return res.send(resp.data)                
//             // const requestToFullFill = url.parse(clientUrl);
//             // console.log({requestToFullFill})
//             // const options = {
//             //     method: req.method,
//             //     headers:req.headers,
//             //     host: req.hostname,
//             //     port: requestToFullFill.port || 8093,
//             //     path: requestToFullFill.path || ''
//             // }
//             // const respData = await proxyRequest(options, req, res) as any;
//             // console.log({respData})
//             // return res.send(respData);


//         }
//         const info = utils.jwts.verifyToken(hasAccess, 'access') as VerifiedToken;
//         if(!info || !info.isVerified || info.expired) return next(new ErrorResponse("Cannot verify", 404)) 
//         if(!orgExists){
//             exists.consents = [...exists.consents, orgId]
//             await exists.save()
//         }
//         const data = {
//             id: exists._id,
//             phoneVerified: exists.phoneVerified,
//             emailVerified: exists.emailVerified
//         }
//         const orgKey = utils.keys.readKey('OrganizationAuthPublicKey', path.join(__dirname, '../../serverKeys/publicKeys'))
//         console.log({orgKey})
//         const encrypted = utils.keys.encryptWithPublic(orgKey, JSON.stringify(data));
//         console.log({encrypted})
//         console.log({encrypted});
//         const resp = await proxy(`${redirect}?${qs.stringify({code: encrypted})}`)
//         console.log({resp})
//         return next()
//     }
//     catch(err){
//         return res.status(500).json({
//             success: false,
//             message: "Can not proxy"
//         })
//     }
// }