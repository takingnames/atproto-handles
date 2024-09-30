import * as namedrop from './lib/namedrop-js/index.js';
import * as atproto from './atproto.js';

class Main extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {

    const tmpl = cloneTemplate('main-template');

    const contentEl = tmpl.querySelector('.content');

    let page;

    (async () => {
      const atClient = await atproto.checkLogin();

      if (atClient) {
        const url = new URL(window.location);
        const params = new URLSearchParams(url.search);

        const state = params.get('state');
        const code = params.get('code');

        // Detect TakingNames oauth callback
        if (state && code) {
          page = document.createElement('status-page');
          page.atClient = atClient;
        }
        else {
          page = document.createElement('logged-in-page');
          page.atClient = atClient;
        }
      }
      else {
        page = document.createElement('login-page');
      }

      contentEl.appendChild(page);
    })();

    this.addEventListener('logout', (evt) => {
      //window.location = '/';
      contentEl.removeChild(page);

      page = document.createElement('login-page');
      contentEl.appendChild(page);
    });

    this.addEventListener('connected', (evt) => {
    });


    this.appendChild(tmpl);
  }
}

class LoginPage extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const tmpl = cloneTemplate('login-page');

    const loginBtn = tmpl.querySelector('#login-btn');

    loginBtn.addEventListener('click', (evt) => {
      evt.preventDefault();
      atproto.login('bsky.social');
    });


    this.appendChild(tmpl);
  }
}

class LoggedInPage extends HTMLElement {
  constructor() {
    super();
  }

  get atClient() {
    return this._atClient;
  }

  set atClient(_) {
    this._atClient = _;
  }

  connectedCallback() {
    const tmpl = cloneTemplate('logged-in-page');

    const userIdEl = tmpl.querySelector('#user-id');
    userIdEl.innerText = this.atClient.handle;

    const logoutBtn = tmpl.querySelector('#logout-btn');
    logoutBtn.addEventListener('click', (evt) => {
      evt.preventDefault();
      atproto.logout();
      emitEvent(this, 'logout');
    });

    const tnBtn = tmpl.querySelector('#tn-btn');
    tnBtn.addEventListener('click', async (evt) => {
      await namedrop.startAuthFlow({ scopes: [ namedrop.SCOPE_ATPROTO_HANDLE ] });
    });

    this.appendChild(tmpl);
  }
}

class StatusPage extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const tmpl = cloneTemplate('status-page');

    const statusText = tmpl.querySelector('#status-text'); 

    (async () => {
      const ndClient = await namedrop.checkAuthFlow(); 
      if (ndClient) {
        setRecords(this.atClient, ndClient, statusText);
      }
    })();

    this.appendChild(tmpl);
  }
}

async function setRecords(atClient, ndClient, statusText) {

  if (ndClient.permissions.length !== 1) {
    throw new Error("Wrong number of perms");
  }

  const domain = ndClient.permissions[0].domain;
  const host = ndClient.permissions[0].host;

  ndClient.setRecords({
    records: [
      {
        domain,
        host: host ? `_atproto.${host}` : '_atproto.',
        type: 'TXT',
        value: `did=${atClient.did}`,
      }
    ],
  });

  const newHandle = host ? `${host}.${domain}` : domain;

  const failHtml = `Failed to update handle. <a href='${window.location.href}'>Restart</a>.`;

  let attemptNum = 1;
  const intId = setInterval(async () => {

    if (attemptNum > 10) {
      clearInterval(intId);
      statusText.innerHTML = failHtml;
      return;
    }

    statusText.innerText = `Handle submitted. This should only take a few seconds to verify. Checking once per second (attempt ${attemptNum})`;
    attemptNum += 1;

    const did = await atClient.resolveHandle(newHandle);

    if (did === atClient.did) {
      clearInterval(intId);

      try {
        await atClient.updateHandle(newHandle);
      }
      catch (e) {
        console.log(e);
        statusText.innerHTML = failHtml;
        return;
      }
      statusText.innerText = "Successfully updated handle";
    }
  }, 1000);
}

function cloneTemplate(templateId) {
  const template = document.getElementById(templateId);
  const docFrag = template.content.cloneNode(true);
  return docFrag;
}

function emitEvent(el, name, detail) {
  el.dispatchEvent(new CustomEvent(name, {
    bubbles: true,
    detail,
  }));
}

customElements.define('custom-handle-main', Main);
customElements.define('logged-in-page', LoggedInPage);
customElements.define('login-page', LoginPage);
customElements.define('status-page', StatusPage);
