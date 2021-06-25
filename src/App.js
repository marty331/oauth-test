import { useEffect, useState } from 'react';
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Link
} from "react-router-dom";
import './App.css';

var config = {
  client_id: process.env.REACT_APP_CLIENT_ID,
  redirect_uri: "http://localhost:3000/auth/callback",
  authorization_endpoint: process.env.REACT_APP_AUTH_ENDPOINT,
  token_endpoint: process.env.REACT_APP_TOKEN_ENDPOINT,
  requested_scopes: "email profile openid"
};

function App() {
  return (
    <Router>
      <div>
        <ul>
          <li>
            <Link to="/">Home</Link>
          </li>
          
        </ul>

        <Switch>
          <Route path="/">
            <Home />
          </Route>
          <Route exact path="/auth/callback" component={() => null} />
        </Switch>
      </div>
    </Router>
  );
}

export default App;

function Home() {

  const [token, setToken] = useState(null)
  const [id_token, setIdToken] = useState(null)
  const [user, setUser] = useState(null)
  const [email, setEmail] = useState(null)
  const [pkce_state, setPkce] = useState(null)
  const [expired, setExpired] = useState(false)

  useEffect(() => {
    var foundToken = false
    var q = parseQueryString(window.location.search.substring(1));
    console.log("q ", q)

    const getAuth = () => {
      sendPostRequest(config.token_endpoint, {
        grant_type: "authorization_code",
        code: q.code,
        client_id: config.client_id,
        redirect_uri: config.redirect_uri,
        code_verifier: localStorage.getItem("pkce_code_verifier")
      });
    }

    // Check if the server returned an error string
    if(q.error) {
        alert("Error returned from authorization server: "+q.error);
        document.getElementById("error_details").innerText = q.error+"\n\n"+q.error_description;
        document.getElementById("error").classList = "";
    }

    // If the server returned an authorization code, attempt to exchange it for an access token
    if(q.code) {

        // Verify state matches what we set at the beginning
        if(localStorage.getItem("pkce_state") !== q.state) {
            console.log("Invalid state");
        } else {
          if(localStorage.getItem('access_token') === null){
            // Exchange the authorization code for an access token
            getAuth()
            // Clean these up since we don't need them anymore
            localStorage.removeItem("pkce_state");
            localStorage.removeItem("pkce_code_verifier");
          }
            
        }
      }    
  },[pkce_state, expired])
  useEffect(() =>{
    if(localStorage.getItem('access_token')) {
      console.log('trying userinfo')
      const userinfo_endpoint = process.env.REACT_APP_USERINFO_ENDPOINT 
          const  headers = new Headers();
          headers.append('Authorization', 'Bearer ' + localStorage.getItem('access_token'))
          headers.append('Content-Type', 'application/x-www-form-urlencoded')
          let req = new Request(userinfo_endpoint, {
            mode: 'cors',
            method: 'GET',
            cache: "no-cache",
            headers: headers,
          });
          fetch(req)
          .then(response => response.json())
          .then(payload => {
            console.log("user payload ", payload)
            setUser(payload.uid)
            setEmail(payload.mail)
            document.getElementById("user").classList = "";
            document.getElementById("user_id").innerText = payload.uid;
            document.getElementById("email").classList = "";
            document.getElementById("email_address").innerText = payload.mail;
          })
          .catch((error) => {
            console.log('user info error ', error)
            document.getElementById("error_details").innerText = error.error+"\n\n"+error.error_description;
            document.getElementById("error").classList = "";
            setExpired(true)
          })
    }
  },[token])

  function authSuccess(body) {

    // Initialize your application now that you have an access token.
    // Here we just display it in the browser.
    console.log("body ", body)
    document.getElementById("access_token").innerText = body.access_token;
    localStorage.setItem('access_token', body.access_token)
    localStorage.setItem('refresh_token', body.refresh_token)
    setToken(body.access_token)
    setIdToken(body.id_token)
    localStorage.setItem('id_token', body.id_token)
    // if(body.id_token){
    //   foundToken = true
    // }
    document.getElementById("start").classList = "hidden";
    document.getElementById("token").classList = "";

    // Replace the history entry to remove the auth code from the browser address bar
    window.history.replaceState({}, null, "/");

  }
  function authFailed(request, error) {
    // This could be an error response from the OAuth server, or an error because the 
    // request failed such as if the OAuth server doesn't allow CORS requests
    document.getElementById("error_details").innerText = error.error+"\n\n"+error.error_description;
    document.getElementById("error").classList = "";
  }

  async function  signIn(e){
    e.preventDefault();
      
    // Create and store a random "state" value
    var state = generateRandomString();
    localStorage.setItem("pkce_state", state);
    setPkce(state)

    // Create and store a new PKCE code_verifier (the plaintext random secret)
    var code_verifier = generateRandomString();
    localStorage.setItem("pkce_code_verifier", code_verifier);

    // Hash and base64-urlencode the secret to use as the challenge
    var code_challenge = await pkceChallengeFromVerifier(code_verifier);

    // Build the authorization URL
    var url = config.authorization_endpoint 
        + "?response_type=code"
        + "&client_id="+encodeURIComponent(config.client_id)
        + "&state="+encodeURIComponent(state)
        + "&scope="+encodeURIComponent(config.requested_scopes)
        + "&redirect_uri="+encodeURIComponent(config.redirect_uri)
        + "&code_challenge="+encodeURIComponent(code_challenge)
        + "&code_challenge_method=S256"
        ;

    // Redirect to the authorization server
    window.location = url;
  }
  //////////////////////////////////////////////////////////////////////
// GENERAL HELPER FUNCTIONS

// Make a POST request and parse the response as JSON
async function sendPostRequest(url, params) {
  var body = Object.keys(params).map(key => key + '=' + params[key]).join('&');
  const  headers = new Headers();
  headers.append('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
  let req = new Request(url, {
    mode: 'cors',
    method: 'POST',
    headers: headers,
    body: body,
  });
  await fetch(req)
  .then(response => response.json())
  .then(payload => {
    console.log("auth payload ", payload)
    authSuccess(payload)
    
  })
  .catch((err) => {
    console.log('auth error ', err)
    authFailed(err)
  })  
}

// Parse a query string into an object
function parseQueryString(string) {
  if(string === "") { return {}; }
  var segments = string.split("&").map(s => s.split("=") );
  var queryString = {};
  segments.forEach(s => queryString[s[0]] = s[1]);
  return queryString;
}

  //////////////////////////////////////////////////////////////////////
// PKCE HELPER FUNCTIONS

// Generate a secure random string using the browser crypto functions
function generateRandomString() {
  var array = new Uint32Array(28);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Calculate the SHA256 hash of the input text. 
// Returns a promise that resolves to an ArrayBuffer
function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

// Base64-urlencodes the input string
function base64urlencode(str) {
  // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
  // btoa accepts chars only within ascii 0-255 and base64 encodes them.
  // Then convert the base64 encoded to base64url encoded
  //   (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Return the base64-urlencoded sha256 hash for the PKCE challenge
async function pkceChallengeFromVerifier(v) {
  const hashed = await sha256(v);
  return base64urlencode(hashed);
}

  return <>
  <h2>Home</h2>
  <div className="flex-center full-height">
    <div className="content">
        <div  id="start" onClick={signIn}>Click to Sign In</div>
        <div id="token" className="hidden">
            <h2>Access Token</h2>
            <div id="access_token" className="code"></div>
        </div>
        <div id="user" className="hidden">
            <h2>User</h2>
            <div id="user_id" className="code"></div>
        </div>
        <div id="email" className="hidden">
            <h2>Email</h2>
            <div id="email_address" className="code"></div>
        </div>
        <div id="error" className="hidden">
            <h2>Error</h2>
            <div id="error_details" className="code"></div>
        </div>
    </div>
</div>  
  </>;
}

function About() {
  return <h2>About</h2>;
}
