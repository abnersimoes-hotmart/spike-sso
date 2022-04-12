import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import express from 'express';
import handlebars from 'express-handlebars';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import request from 'request-promise';
import { base64URLEncode, sha256, validateIDToken } from './utils.js';

// loading env vars from .env file
dotenv.config();

request.defaults({ family: 4 });

const { HOME_URI } = process.env;
const { OIDC_PROVIDER } = process.env;
const { CONFIGURATION_URL } = process.env;
const { CALLBACK_URI } = process.env;
const { TOKEN_URI } = process.env;
const { CLIENT_ID } = process.env;

let oidcProviderInfo;
const stateCookie = 'auth0rization-state';

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

//assim que abre a página faz uma request no domínio do Idp(ex: CAS) e pega as configurações preliminares. Veja as configs em: https://sso.buildstaging.com/oidc/.well-known/openid-configuration
request(`${OIDC_PROVIDER}${CONFIGURATION_URL}`)
  .then(res => {
    oidcProviderInfo = JSON.parse(res);
    app.listen(3000, () => {
      console.log(`Server running on ${HOME_URI}`);
    });
  })
  .catch(error => {
    console.error(error);
    console.error(
      `Unable to get OIDC endpoints for ${OIDC_PROVIDER}${CONFIGURATION_URL}`
    );
    process.exit(1);
  });

app.get('/', (req, res) => {
  res.render('index');
});

const code_verifier = base64URLEncode(crypto.randomBytes(32));

//Quando clica em "To start the authentication process, click here." ele redireciona para fazer a autenticação la no servidor do IdP
//o endereço do redirecionamento fica na variável `authorization_endpoint` que busca lá das configs carregadas na request que consome o endpoint de openid-configuration
app.get('/login', (req, res) => {
  // define as constantes para o pedido de autorização
  const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
  const scope = 'openid profile email'; //read:to-dos
  const state = crypto.randomBytes(16).toString('hex');
  const code_challenge = base64URLEncode(sha256(code_verifier));

  console.log(`DEBUG - state=${state}`);
  console.log(`DEBUG - code_verifier=${code_verifier}`);
  console.log(`DEBUG - code_challenge=${code_challenge}`);

  // define um cookie assinado contendo o valor state
  const options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  var url =
    authorizationEndpoint +
    `?client_id=${CLIENT_ID}` + //o identificador que o provedor atribui ao seu aplicativo
    `&scope=${scope}` + //as informações que você deseja saber sobre a autenticação de usuários
    '&response_type=code' + //o tipo de resposta que seu aplicativo espera do provedor
    '&response_mode=query' + //como seu aplicativo obterá o tokenId ou code para o usuário final
    `&state=${state}` + //string aleatória que ajuda seu aplicativo a evitar ataques de falsificação de solicitação entre sites (CSRF)
    `&code_challenge=${code_challenge}` +
    '&code_challenge_method=S256' +
    `&redirect_uri=${HOME_URI}${CALLBACK_URI}`; //onde o provedor redirecionará os usuários após o processo de autenticação

  // adicione o cookie à resposta e emite um usuário de redirecionamento 302
  res.cookie(stateCookie, state, options).redirect(url);
});

app.get('/callback', async (req, res) => {
  const tokenEndpoint = oidcProviderInfo['token_endpoint'];
  const state = req.signedCookies[stateCookie]; // pega o state do cookie
  delete req.signedCookies[stateCookie]; // delete state

  const { code } = req.query;

  const codeExchangeOptions = {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code: code,
    redirect_uri: HOME_URI + CALLBACK_URI,
    state: state,
    code_verifier: code_verifier
  };

  const codeExchangeResponse = await request.post(tokenEndpoint, {
    form: codeExchangeOptions
  });

  // parse response to get tokens
  const tokens = JSON.parse(codeExchangeResponse);
  req.session.accessToken = tokens.access_token;
  console.log(`DEBUG - accesstoken: ${req.session.accessToken}`);
  console.log(`DEBUG - refreshToken: ${tokens.refresh_token}`);
  console.log(`DEBUG - idToken: ${tokens.id_token}`);
  console.log(`DEBUG - state: ${state}`);

  try {
    req.session.decodedIdToken = validateIDToken(
      tokens.id_token,
      state,
      oidcProviderInfo['issuer']
    );
    req.session.idToken = tokens.id_token;
    res.redirect('/profile');
  } catch (error) {
    res.status(401).send();
  }
});

app.get('/profile', (req, res) => {
  const { idToken, decodedIdToken } = req.session;
  res.render('profile', {
    idToken,
    decodedIdToken
  });
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
