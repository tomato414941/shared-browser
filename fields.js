// Runs in each frame, in a world of its own that the page cannot see. Tells the screen where the page's fields are
// on the display, so a phone can bring up its keyboard within a tap on one, and of the field with focus, its kind
// and the text before its caret, so the viewer's keyboard can fit it. The screen asks with __sbNext(), which answers
// once something has changed, and with __sbNext(true) when it starts listening, which answers at once.
(() => {
  if (globalThis.__sbNext) return;
  const TEXT = new Set(['text', 'search', 'email', 'url', 'tel', 'password', 'number']);
  const ids = new WeakMap();
  let count = 0, last = '', pending = null, waiting = null, timer = null, due = Infinity, fields = null, moved = 0;

  globalThis.__sbNext = now => new Promise(resolve => {
    if (now) {
      waiting = pending = null;
      resolve(last = JSON.stringify(state()));
    } else if (pending !== null) {
      resolve(pending);
      pending = null;
    } else {
      waiting = resolve;
    }
  });

  function deliver(text) {
    if (waiting) {
      waiting(text);
      waiting = null;
    } else {
      pending = text;
    }
  }

  const editable = el => !!el && !el.disabled && !el.readOnly &&
    (el.localName === 'textarea' || (el.localName === 'input' ? TEXT.has(el.type) : el.isContentEditable));

  function active() {
    let el = document.activeElement;
    while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
    return el;
  }

  // Where this frame's viewport sits on the display. Unknown (null) inside a frame of another site.
  function place() {
    let x = 0, y = 0, w = window;
    try {
      while (w !== w.top) {
        const owner = w.frameElement, r = owner.getBoundingClientRect(), s = getComputedStyle(owner);
        x += r.left + parseFloat(s.borderLeftWidth) + parseFloat(s.paddingLeft);
        y += r.top + parseFloat(s.borderTopWidth) + parseFloat(s.paddingTop);
        w = w.parent;
      }
      const z = w.devicePixelRatio;
      return {x: w.screenX + (w.outerWidth - w.innerWidth * z) / 2 + x * z,
              y: w.screenY + w.outerHeight - w.innerHeight * z + y * z, z};
    } catch (e) {
      return null;
    }
  }

  const box = (r, p) => [Math.round(p.x + r.left * p.z), Math.round(p.y + r.top * p.z),
                         Math.round(r.width * p.z), Math.round(r.height * p.z)];

  // The text before the caret, so the viewer's keyboard can correct and predict as it would in the field itself.
  function before(el) {
    if (el.type === 'password') return '';
    if (el.localName === 'input' || el.localName === 'textarea') {
      const end = el.selectionStart ?? el.value.length;   // email and number fields have no selection
      return el.value.slice(Math.max(0, end - 200), end);
    }
    const selection = getSelection();
    if (!selection.rangeCount) return '';
    const caret = selection.getRangeAt(0), range = document.createRange();
    if (!el.contains(caret.startContainer)) return '';
    range.selectNodeContents(el);
    range.setEnd(caret.startContainer, caret.startOffset);
    return range.toString().slice(-200);
  }

  // Where the caret is, for the viewer's input method to show its candidates beside. Known in rich text only.
  function caret(el, p) {
    if (el.localName === 'input' || el.localName === 'textarea') return null;
    const selection = getSelection();
    const rect = selection.rangeCount && selection.getRangeAt(0).getClientRects()[0];
    return rect ? box(rect, p) : null;
  }

  function visibleFields(p) {
    const found = [], roots = [document];
    for (let i = 0; i < roots.length; i++)
      for (const el of roots[i].querySelectorAll('*')) if (el.shadowRoot) roots.push(el.shadowRoot);
    for (const root of roots) {
      for (const f of root.querySelectorAll('input, textarea, [contenteditable]')) {
        if (found.length === 100) return found;
        if (!editable(f)) continue;
        const r = f.getBoundingClientRect();
        if (r.width >= 4 && r.height >= 4 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth)
          found.push(box(r, p));
      }
    }
    return found;
  }

  // What the screen needs of this frame: its field with focus, when focus last moved here, and its fields.
  function state() {
    const p = place(), el = active(), focused = document.hasFocus(), visible = document.visibilityState === 'visible';
    let focus = null;
    if (focused && editable(el)) {
      if (!ids.has(el)) ids.set(el, ++count);
      focus = {id: ids.get(el), box: p && box(el.getBoundingClientRect(), p), caret: p && caret(el, p),
               kind: el.localName === 'input' ? el.type : 'text', multiline: el.localName !== 'input',
               inputmode: el.inputMode || '', enterkeyhint: el.enterKeyHint || '',
               autocapitalize: el.getAttribute('autocapitalize') || '', before: before(el)};
    }
    if (fields === null) fields = p && visible ? visibleFields(p) : [];
    return {focus, fields, moved};
  }

  function tell() {
    due = Infinity;
    const now = JSON.stringify(state());
    if (now !== last) deliver(last = now);
  }

  // Look again within ms, or sooner if something else asked sooner. Moves look for fields again; typing does not.
  function soon(ms, moved = true) {
    if (moved) fields = null;
    const at = performance.now() + ms;
    if (at >= due) return;
    clearTimeout(timer);
    due = at;
    timer = setTimeout(tell, ms);
  }

  for (const type of ['selectionchange', 'input']) document.addEventListener(type, () => soon(20, false), true);
  for (const type of ['focusin', 'focusout']) {
    document.addEventListener(type, () => {
      moved = Date.now();
      soon(20);
    }, true);
  }
  addEventListener('focus', () => soon(0));
  addEventListener('blur', () => soon(0));
  addEventListener('scroll', () => soon(120), true);
  addEventListener('resize', () => soon(120));
  document.addEventListener('visibilitychange', () => soon(0));
  new MutationObserver(() => soon(300)).observe(document, {subtree: true, childList: true, attributes: true});
  setInterval(() => soon(0), 1000);   // for what moves without an event: animations, fonts, images loading
  // Leaving for the back-forward cache keeps this world alive but asleep: say so, and speak up again on return.
  addEventListener('pagehide', () => deliver(last = '{"gone":true}'));
  addEventListener('pageshow', e => e.persisted && soon(0));
  soon(0);
})();
