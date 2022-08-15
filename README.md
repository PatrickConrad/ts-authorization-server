# ID and Authorization Service 
Id and authorizatio server written in typescript

##Setup
Complete these steps before starting server

Run npm
- Run: *npm install* in the command line
  installs all dependencies

Add required environment variables
- create a .env config file in the src/config folder

- set up variables for 
NODE_ENV
PORT
TOKEN_AUTHORITY (site domain)
REDIS_PORT
PASSWORD_SALT_ROUNDS (defaults if not specified, can set salt for specific password setups too using built in function in src/utils/keys file)
DB_PROTOCOL
DB_IP
DB_NAME

-set up google login access
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_CLIENT_REDIRECT_URL
GOOGLE_OAUTH_REDIRECT_URL

- generate secret keys for... (you can use the built in function in the src/utils/keys folder)
ORGANIZATION_PHONE_TOKEN_PASSPHRASE
USER_SERVICE_TOKEN_PASSPHRASE
ORGANIZATION_AUTH_TOKEN_PASSPHRASE
CARRIER_TOKEN_PASSPHRASE
LOGIN_TOKEN_PASSPHRASE
ACCESS_TOKEN_PASSPHRASE
REFRESH_TOKEN_PASSPHRASE
RESET_PW_TOKEN_PASSPHRASE
FORGOT_PW_TOKEN_PASSPHRASE
VERIFY_TOKEN_PASSPHRASE
EMAIL_TOKEN_PASSPHRASE
PHONE_TOKEN_PASSPHRASE
ORGANIZATION_EMAIL_TOKEN_PASSPHRASE

- set expiration times in MS for...
EMAIL_TOKEN_EXPIRES
PHONE_TOKEN_EXPIRES
VERIFY_TOKEN_EXPIRES
FORGOT_PW_TOKEN_EXPIRES
RESET_PW_TOKEN_EXPIRES
REFRESH_TOKEN_EXPIRES
ACCESS_TOKEN_EXPIRES
LOGIN_TOKEN_EXPIRES
CARRIER_TOKEN_EXPIRES

- create a serverKeys folder in the root and inside create two folders privateKeys and publicKeys
  -- use the built in function in the src/utils/keys file to generate and write pem keys to files automatically
  -- need private keys for...
  AccessPrivateKey
  EmailPrivateKey
  ForgotPwPrivateKey
  LoginPrivateKey
  OrganizationAuthPrivateKey
  OrgEmailPrivateKey
  PhonePrivateKey
  RefreshPrivateKey
  ResetPwPrivateKey
  CarrierPrivateKey
  UserAccessPrivateKey
  VerifyPrivateKey
  
  -- need public keys for...
  AccessPublicKey
  EmailPublicKey
  ForgotPwPublicKey
  LoginPublicKey
  OrganizationAuthPublicKey
  OrgEmailPublicKey
  OrgInvitePublicKey
  PhonePublicKey
  RefreshPublicKey
  ResetPwPublicKey
  CarrierPublicKey
  UserAccessPublicKey
  VerifyPublicKey

- API routes as of 8/15/23 have not been fully tested, but basic login features are functioning

- still need to:
test all routes (specifically resets, forgot password, organization related, change phone, change email)

figure out how to set cookies and redirect allow user server to set cookies and redirect back to their frontend with cookies set after making a login request to the org server (seperate)

