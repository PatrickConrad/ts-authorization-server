import {AuthIframe} from './iframeClass';

export type SetAuth = (window: Window, iframe: HTMLIFrameElement, styles: string)=>void;

export type ConsentResponse = (src: string, auth: AuthIframe)=>{
    src: string,
    auth: AuthIframe
}


export const consentResponse: ConsentResponse = (src: string, auth: AuthIframe) =>{
    return {src, auth}
}