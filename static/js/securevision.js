/* SecureVision UI helpers. Presentation only: identity, permissions and
   validation are always decided on the server. */
(function () {
  'use strict';

  function each(selector, fn) {
    Array.prototype.forEach.call(document.querySelectorAll(selector), fn);
  }

  /* ---- Mobile navigation ---- */
  var toggle = document.querySelector('[data-nav-toggle]');
  var scrim = document.querySelector('[data-nav-close]');
  function setNav(open) {
    document.body.classList.toggle('nav-open', open);
    if (toggle) {
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    }
    if (scrim) { scrim.hidden = !open; }
  }
  if (toggle) {
    toggle.addEventListener('click', function () {
      setNav(!document.body.classList.contains('nav-open'));
    });
  }
  if (scrim) { scrim.addEventListener('click', function () { setNav(false); }); }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { setNav(false); }
  });

  /* ---- Show / hide password ---- */
  each('[data-toggle-password]', function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-toggle-password'));
      if (!input) { return; }
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      var use = btn.querySelector('use');
      if (use) { use.setAttribute('href', show ? '#i-eye-off' : '#i-eye'); }
    });
  });

  /* ---- Live password checklist (mirrors accounts.validators) ---- */
  var RULES = {
    length: function (v) { return v.length >= 8; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    digit: function (v) { return /[0-9]/.test(v); },
    special: function (v) { return /[^A-Za-z0-9\s]/.test(v); }
  };
  each('[data-pw-rules]', function (list) {
    var input = document.getElementById(list.getAttribute('data-pw-rules'));
    if (!input) { return; }
    function update() {
      Array.prototype.forEach.call(list.querySelectorAll('[data-rule]'), function (item) {
        var check = RULES[item.getAttribute('data-rule')];
        item.classList.toggle('is-met', !!check && check(input.value));
      });
    }
    input.addEventListener('input', update);
    update();
  });

  /* ---- Confirm-password match ---- */
  each('[data-pw-match]', function (msg) {
    var first = document.getElementById(msg.getAttribute('data-pw-match'));
    var second = document.getElementById(msg.getAttribute('data-pw-target'));
    if (!first || !second) { return; }
    function update() {
      if (!second.value) {
        msg.textContent = '';
        msg.className = 'pw-match';
        return;
      }
      var ok = first.value === second.value;
      msg.textContent = ok ? 'Passwords match.' : 'Passwords do not match.';
      msg.className = 'pw-match ' + (ok ? 'is-ok' : 'is-bad');
    }
    first.addEventListener('input', update);
    second.addEventListener('input', update);
  });

  /* ---- Sign-up role dropdown: show the role's description and, for
         Team Leader / Admin, the authorization-code field. The server
         still validates the code; this only controls what is shown. ---- */
  var roleSelect = document.querySelector('[data-role-select]');
  if (roleSelect) {
    var codeWrap = document.querySelector('[data-role-code-wrap]');
    var syncRole = function () {
      var value = roleSelect.value;
      each('[data-role-help]', function (p) {
        p.hidden = p.getAttribute('data-role-help') !== value;
      });
      if (codeWrap) { codeWrap.hidden = (value === 'EMPLOYEE' || !value); }
    };
    roleSelect.addEventListener('change', syncRole);
    syncRole();
  }

  /* ---- Confirmation for destructive forms ---- */
  each('form[data-confirm]', function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) { e.preventDefault(); }
    });
  });
})();
/* Phase 2: filter a list of options (e.g. the add-members picker). */
(function () {
  'use strict';
  Array.prototype.forEach.call(document.querySelectorAll('[data-filter-input]'), function (input) {
    var list = document.getElementById(input.getAttribute('data-filter-input'));
    if (!list) { return; }
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); }
    });
    input.addEventListener('input', function () {
      var query = input.value.trim().toLowerCase();
      Array.prototype.forEach.call(list.querySelectorAll('[data-filter-item]'), function (item) {
        item.hidden = query !== '' && item.getAttribute('data-filter-item').indexOf(query) === -1;
      });
    });
  });
})();
/* Phase 4/5: live chat. Progressive enhancement only - the server checks every
   send, delete and read. Messages are inserted with textContent, never HTML. */
(function () {
  'use strict';
  var list = document.querySelector('[data-chat]');
  if (!list) { return; }
  var composer = document.querySelector('[data-composer]');
  var errorBox = document.querySelector('[data-composer-error]');
  var updatesUrl = list.getAttribute('data-updates-url');
  var conversationId = list.getAttribute('data-conversation');
  var lastId = parseInt(list.getAttribute('data-last-id'), 10) || 0;
  var tokenInput = document.querySelector('input[name="csrfmiddlewaretoken"]');
  var csrf = tokenInput ? tokenInput.value : '';
  var CONFIRM = 'Delete this message? Everyone in the conversation will see "Message deleted".';

  function scrollToEnd() { list.scrollTop = list.scrollHeight; }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function setPreview(text) {
    var preview = document.querySelector('[data-preview="' + conversationId + '"]');
    if (!preview) { return; }
    var flat = text.replace(/\s+/g, ' ').trim();
    preview.textContent = flat.length > 60 ? flat.slice(0, 60) + '...' : flat;
  }

  function buildMenu(url) {
    var details = el('details', 'msg-menu');
    var summary = el('summary', '', '\u00b7\u00b7\u00b7');
    summary.setAttribute('aria-label', 'Message options');
    var form = el('form');
    form.method = 'post';
    form.action = url;
    var token = el('input');
    token.type = 'hidden';
    token.name = 'csrfmiddlewaretoken';
    token.value = csrf;
    var button = el('button', 'btn btn-sm btn-danger-ghost', 'Delete');
    button.type = 'submit';
    form.appendChild(token);
    form.appendChild(button);
    form.addEventListener('submit', function (e) {
      if (!window.confirm(CONFIRM)) { e.preventDefault(); }
    });
    details.appendChild(summary);
    details.appendChild(form);
    return details;
  }

  function buildMessage(m) {
    var li = el('li', 'msg' + (m.mine ? ' msg--mine' : '') +
      (m.announcement ? ' msg--announcement' : '') + (m.deleted ? ' msg--deleted' : ''));
    li.setAttribute('data-message-id', m.id);
    var meta = el('div', 'msg-meta');
    meta.appendChild(el('strong', '', m.mine ? 'You' : m.sender));
    meta.appendChild(el('time', '', m.time));
    if (m.announcement) { meta.appendChild(el('span', 'tag tag-accent', 'Announcement')); }
    li.appendChild(meta);
    var body = el('div', 'msg-body');
    if (m.deleted) { body.appendChild(el('em', '', 'Message deleted')); } else { body.textContent = m.body; }
    li.appendChild(body);
    if (m.delete_url) { li.appendChild(buildMenu(m.delete_url)); }
    return li;
  }

  function append(m) {
    if (list.querySelector('[data-message-id="' + m.id + '"]')) { return; }
    var empty = list.querySelector('[data-empty]');
    if (empty) { empty.parentNode.removeChild(empty); }
    var nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 120;
    list.appendChild(buildMessage(m));
    lastId = Math.max(lastId, m.id);
    setPreview(m.deleted ? 'Message deleted' : m.body);
    if (m.mine || nearBottom) { scrollToEnd(); }
  }

  function markDeleted(id) {
    var li = list.querySelector('[data-message-id="' + id + '"]');
    if (!li || li.classList.contains('msg--deleted')) { return; }
    li.classList.add('msg--deleted');
    var body = li.querySelector('.msg-body');
    body.textContent = '';
    body.appendChild(el('em', '', 'Message deleted'));
    var menu = li.querySelector('.msg-menu');
    if (menu) { menu.parentNode.removeChild(menu); }
    if (!li.nextElementSibling) { setPreview('Message deleted'); }
  }

  function poll() {
    fetch(updatesUrl + '?after=' + lastId, {
      credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' }
    }).then(function (response) {
      return response.json();
    }).then(function (data) {
      data.messages.forEach(append);
      data.deleted.forEach(markDeleted);
    }).catch(function () { /* offline or signed out: try again next time */ });
  }

  if (composer) {
    var textarea = composer.querySelector('textarea');
    var button = composer.querySelector('button[type="submit"]');
    var send = function () {
      if (!textarea.value.trim()) { return; }
      button.disabled = true;
      fetch(composer.action, {
        method: 'POST', body: new FormData(composer), credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      }).then(function (response) {
        return response.json().then(function (data) { return { ok: response.ok, data: data }; });
      }).then(function (result) {
        if (result.ok) {
          textarea.value = '';
          errorBox.hidden = true;
          var announce = composer.querySelector('[name="announcement"]');
          if (announce) { announce.checked = false; }
          append(result.data.message);
        } else {
          errorBox.textContent = result.data.error || 'Message not sent.';
          errorBox.hidden = false;
        }
      }).catch(function () {
        errorBox.textContent = 'Message not sent. Check your connection and try again.';
        errorBox.hidden = false;
      }).then(function () {
        button.disabled = false;
        textarea.focus();
      });
    };
    composer.addEventListener('submit', function (e) { e.preventDefault(); send(); });
    textarea.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
    });
  }

  scrollToEnd();
  window.setInterval(poll, 4000);
})();

/* Phase 5: live "working duration" on the Attendance page while checked in. */
(function () {
  'use strict';
  var node = document.querySelector('[data-since]');
  if (!node) { return; }
  var since = new Date(node.getAttribute('data-since'));
  if (isNaN(since.getTime())) { return; }
  function render() {
    var minutes = Math.max(0, Math.floor((Date.now() - since.getTime()) / 60000));
    var mm = minutes % 60;
    node.textContent = Math.floor(minutes / 60) + 'h ' + (mm < 10 ? '0' : '') + mm + 'm';
  }
  render();
  window.setInterval(render, 30000);
})();

/* Phase 9: print buttons (no inline onclick, so the Content-Security-Policy can forbid inline scripts). */
(function () {
  'use strict';
  var buttons = document.querySelectorAll('[data-print]');
  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener('click', function () { window.print(); });
  });
})();