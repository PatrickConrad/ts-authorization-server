//this is where devices are registered
    //get device id from a cookie set on register and updated each login?
    //check for available device bio metrics. Present options to user to register biometrics of availibility or if none use password and 2pt. if requrired
    //save public key and required info for each device 
    //check if device has app or pwa installed
    //get consent for using device as a 2pt auth system via biometrics

//if device registered and has pwa it can be used to request authentication via biometrics
    //register by geting device info, ip, country of origin, browser
    //or use other device authenticators
    //index ip by ranges and use to find country --- faster searching


//else if user is on device when making login request, they can use biometrics to login

//generate challenge for webauthn on request by client

//verify biometrics 