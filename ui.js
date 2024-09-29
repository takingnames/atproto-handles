import * as namedrop from './lib/namedrop-js/index.js';
import * as atproto from './atproto.js';

class Main extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {

    const tmpl = cloneTemplate('main-template');

    const contentEl = tmpl.querySelector('.content');

    (async () => {
      const atClient = await atproto.checkLogin();

      let page;
      if (atClient) {
        page = document.createElement('logged-in-page');
        page.atClient = atClient;
      }
      else {
        page = document.createElement('login-page');
      }

      contentEl.appendChild(page);
    })();

    this.addEventListener('logout', (evt) => {
      window.location = '/';
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

    loginBtn.addEventListener('click', () => {
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
      atproto.logout();
      emitEvent(this, 'logout');
    });



    namedrop.setApiUri('https://dev.takingnames.io/namedrop');

    const tnBtn = tmpl.querySelector('#tn-btn');
    tnBtn.addEventListener('click', async (evt) => {
      await namedrop.startAuthFlow({ scopes: [ namedrop.SCOPE_ATPROTO_HANDLE ] });
    });

    const statusText = tmpl.querySelector('#status-text');
    checkNamedrop(this.atClient, statusText);

    this.appendChild(tmpl);
  }
}

async function checkNamedrop(atClient, statusText) {
  const ndClient = await namedrop.checkAuthFlow(); 
  if (ndClient) {

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

    let attemptNum = 1;
    const intId = setInterval(async () => {

      statusText.innerText = `Checking handle (attempt ${attemptNum})...`;
      attemptNum += 1;

      const did = await atClient.resolveHandle(newHandle);

      if (did === atClient.did) {
        clearInterval(intId);

        await atClient.updateHandle(newHandle);
        statusText.innerText = "Successfully set handle";
      }
    }, 1000);
  }
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
