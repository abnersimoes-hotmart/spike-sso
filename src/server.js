const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const request = require('request-promise').defaults({ family: 4 });
const session = require('express-session');

// loading env vars from .env file
require('dotenv').config();

const {OIDC_PROVIDER} = process.env;
const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`;

const nonceCookie = 'auth0rization-nonce';
let oidcProviderInfo;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/profile', (req, res) => {
  const { idToken, decodedIdToken } = req.session;
  res.render('profile', {
    idToken,
    decodedIdToken
  });
});

app.get('/remove-to-do/:id', async (req, res) => {
  res.status(501).send();
});


//ONDE TUDO COMEÇA

//assim que abre a página faz uma request no domínio do Idp(ex: CAS) e pega as configurações preliminares
//Veja as configs em: https://dev-9lg81ot7.us.auth0.com/.well-known/openid-configuration
//ou em: https://sso.buildstaging.com/oidc/.well-known/openid-configuration
request(discEnd).then((res) => {
  oidcProviderInfo = JSON.parse(res);
  app.listen(3000, () => {
    console.log(`Server running on http://localhost:3000`);
  });
}).catch((error) => {
  console.error(error);
  console.error(`Unable to get OIDC endpoints for ${OIDC_PROVIDER}`);
  process.exit(1);
});

//Quando clica em "To start the authentication process, click here." ele redireciona para fazer a autenticação la no servidor do IdP
//o endereço do redirecionamento fica na variável `authorization_endpoint` que busca lá das configs carregadas na request que consome o endpoint de openid-configuration
app.get('/login', (req, res) => {
  // define as constantes para o pedido de autorização
  const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
  const responseType = 'code'; //'id_token', 'code';
  const scope = 'openid profile email read:to-dos';
  const clientID = process.env.CLIENT_ID;
  var redirectUri = 'http://localhost:3000/callback';
  const responseMode = 'query'; //'form_post', 'query'
  const nonce = crypto.randomBytes(16).toString('hex');
  const audience = process.env.API_IDENTIFIER;

  if(clientID == 'eb33d28d-39e2-4e0c-88da-6b7cab31c812') redirectUri = 'https://oidc-client-playground.buildstaging.com/code-identityserver-sample.html';

  // define um cookie assinado contendo o valor nonce
  const options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // O cookie acessível apenas pelo servidor web
    signed: true // Indica se o cookie deve ser assinado
  };

  var url = authorizationEndpoint +
  '?client_id=' + clientID + //o identificador que o provedor atribui ao seu aplicativo
  '&redirect_uri='+ redirectUri + //Onde o provedor redirecionará os usuários após o processo de autenticação
  '&response_type=' + responseType + //o tipo de resposta que seu aplicativo espera do provedor
  '&scope=' + scope + //as informações que você deseja saber sobre a autenticação de usuários
  '&response_mode=' + responseMode + //como seu aplicativo obterá o token de ID para o usuário final
  '&nonce='+ nonce + //uma string aleatória que ajuda seu aplicativo a evitar ataques de repetição
  '&state=2fbd2045bb4e4058a75b71194cf559ea' + //uma string aleatória que ajuda seu aplicativo a evitar ataques de falsificação de solicitação entre sites
  '&audience=' + audience

  if(clientID == 'eb33d28d-39e2-4e0c-88da-6b7cab31c812') url = url + '&code_challenge=ia2biZy-d2p6L4xm7h8pIMS2gYtHkKMvW3gVcBk-5IY&code_challenge_method=S256' //descobrir o que é isso no CAS

  // add cookie to the response and issue a 302 redirecting user
  res
    .cookie(nonceCookie, nonce, options)
    .redirect(url);
});

function validateIDToken(idToken, nonce) {
  const decodedToken = jwt.decode(idToken);
  // fetch ID token details
  const {
    nonce: decodedNonce,
    aud: audience,
    exp: expirationDate,
    iss: issuer
  } = decodedToken;
  const currentTime = Math.floor(Date.now() / 1000);
  const expectedAudience = process.env.CLIENT_ID;

  // validate ID tokens
  if (
    audience !== expectedAudience ||
    decodedNonce !== nonce ||
    expirationDate < currentTime ||
    issuer !== oidcProviderInfo['issuer']
  )
  throw Error();

  // return the decoded token
  return decodedToken;
}

app.get('/callback', async (req, res) => {
  const { code } = req.query;
  const codeExchangeOptions = {
    grant_type: 'authorization_code',
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    code: code,
    redirect_uri: 'http://localhost:3000/callback'
  };
  const codeExchangeResponse = await request.post(
    `https://${process.env.OIDC_PROVIDER}/oauth/token`,
    { form: codeExchangeOptions }
  );

  // parse response to get tokens
  const tokens = JSON.parse(codeExchangeResponse);
  req.session.accessToken = tokens.access_token;
  console.log(`accesstoken ${req.session.accessToken}`)
  
  // extract nonce from cookie
  const nonce = req.signedCookies[nonceCookie];
  delete req.signedCookies[nonceCookie];
  try {
    req.session.decodedIdToken = validateIDToken(tokens.id_token, nonce);
    req.session.idToken = tokens.id_token;
    res.redirect('/profile');
  } catch (error) {
    res.status(401).send();
  }
});

app.get('/to-dos', async (req, res) => {
  const delegatedRequestOptions = {
    url: 'http://localhost:3001',
    headers: {
      Authorization: `Bearer ${req.session.accessToken}`
    }
  };

  try {
    const delegatedResponse = await request(delegatedRequestOptions);
    const toDos = JSON.parse(delegatedResponse);

    res.render('to-dos', { toDos });
  } catch (error) {
    res.status(error.statusCode).send(error);
  }
});

// app.post('/callback', async (req, res) => {
//   const nonce = req.signedCookies[nonceCookie]; // take nonce from cookie
//   delete req.signedCookies[nonceCookie]; // delete nonce

//   const {id_token} = req.body; // take ID Token posted by the user
//   const decodedToken = jwt.decode(id_token, {complete: true}); // decode token
//   const kid = decodedToken.header.kid; // get key id

//   // get public key
//   const client = jwksClient({
//     jwksUri: oidcProviderInfo['jwks_uri'],
//   });
 
//   client.getSigningKey(kid, (err, key) => {
//     const signingKey = key.publicKey || key.rsaPublicKey;
//     // verify signature & decode token
//     const verifiedToken = jwt.verify(id_token, signingKey);
//     // check audience, nonce, and expiration time
//     const {
//       nonce: decodedNonce, //Como mencionado anteriormente, para evitar ataques de repetição também é importante confirmar que o Provedor OpenID Connect anexado ao ID Token com o mesmo valor nonce do aplicativo gerado na construção do pedido de autorização.
//       aud: audience, //é importante confirmar que o token foi criado para este aplicativo em particular. Portanto, o expectAudience (a declaração de auditoria) deve ser o CLIENT_ID definido pelo provedor quando você registrou seu aplicativo lá.
//       exp: expirationDate, //Outra característica importante dos ID Tokens é que a hora atual deve ser antes do tempo representado pela declaração exp.
//       iss: issuer //Por último, mas igualmente importante, é que o emissor (a reivindicação iss) do token deve ser seu provedor OIDC.
//     } = verifiedToken;
//     const currentTime = Math.floor(Date.now() / 1000);
//     const expectedAudience = process.env.CLIENT_ID;
//     if (audience !== expectedAudience || decodedNonce !== nonce || expirationDate < currentTime || issuer !== oidcProviderInfo['issuer']) {
//       // send an unauthorized http status
//       return res.status(401).send();
//     }
//     req.session.decodedIdToken = verifiedToken;
//     req.session.idToken = id_token;

//     // send the decoded version of the ID Token
//     res.redirect('/profile');
//   });
// });