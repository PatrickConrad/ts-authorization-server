import axios from 'axios';

interface MessageData {
    type: string,
    value: string
}

export class AuthIframe {
    private window: Window | null= null;
    private iframe: HTMLIFrameElement | null = null;
    private secret;
    private orgOrigin;
    private originDomain = process.env.NODE_ENV==='development'?`http://localhost:`+process.env.PORT:process.env.SITE_DOMAIN as string 
    constructor(origin: string, secret: string){
        this.secret = secret;
        this.orgOrigin = origin;
    }
    private sendKey() {
        if(this.iframe === null) return;
        this.iframe.contentWindow?.postMessage({type: 'key'}, 'http://localhost:3000')
        return;
    }
    private async onSuccess(url: string){
        try{
            if(this.window === null) return;
            let response = await this.window.fetch(url, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json;charset=utf-8'
                },
                body: '',
                credentials: "include"
              });
            const res = await response.json();
            console.log({res});
            return
        }
        catch(err: any){
            console.log({error: {message: 'cant send to server', err}})
            return;
        }
    }
    
    private checkMessage(message: MessageData){
        if(message.type === 'keyRequst') this.sendKey();
        if(message.type === 'onSuccess') this.onSuccess(message.value)
        return;
    }

    private actionCall(e: MessageEventInit<MessageData>){
        if(this.window === null) return;
        if(!e.origin || e.origin !== this.window.location.hostname || !e.data) {
            console.log("origin not matched")
            return
        }
        const data: MessageData = e.data
        this.checkMessage(data)
        return;
    }
    public init(window: Window, iframe: HTMLIFrameElement, styles: string){
        this.iframe=iframe;
        this.window=window;
        const value = JSON.stringify({origin: this.orgOrigin, styles, secret: this.secret})
        iframe.contentWindow?.postMessage({type: 'init', value}, 'http://localhost:3000')
        this.secret = '';
        return;
    }
    public setListener(){
        if(this.window === null) return;
        this.window.addEventListener('message', (e: MessageEventInit<MessageData>)=>this.actionCall(e))
        return;
    }
    public removeListener(){
        if(this.window === null) return;
        this.window.removeEventListener('message', (e: MessageEventInit<MessageData>)=>this.actionCall(e))
        return
    }

}