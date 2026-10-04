// Before the client is built: strip the neko name and logo so the viewer carries no brand, and remove its login
// form. The gate has already let the person in, so the client joins the screen under the name the gate gives.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2];
const edit = (path, fn) => {
  const file = join(root, path);
  const before = readFileSync(file, "utf8");
  const after = fn(before);
  if (after === before) throw new Error(`nothing changed in ${path}`);
  writeFileSync(file, after);
};
const logoBlock = /<div class="logo"[^>]*>[\s\S]*?<\/div>\n/;

edit("src/components/connect.vue", s => s.replace(logoBlock, ""));
edit("src/components/connect.vue", s => s.replace(/ *<form class="message"[\s\S]*?<\/form>\n/, ""));
edit("src/components/connect.vue", s => s.replace('<div class="loader" v-if="connecting">', '<div class="loader">'));
edit("src/components/connect.vue", s => s.replace(/    mounted\(\) \{[\s\S]*?\n    \}\n(?=\n    get connecting\(\))/, `    mounted() {
      fetch('./whoami', { credentials: 'same-origin' })
        .then((res) => (res.ok ? res.json() : Promise.reject()))
        .then((who) => this.$accessor.login({ displayname: who.name, password: '-' }))
        .catch(() => location.reload())
    }
`));
edit("src/components/unsupported.vue", s => s.replace(logoBlock, ""));
// Leaving is closing the page; a logout that the gate does not know about would only strand the person.
edit("src/components/settings.vue", s => s.replace(/ *<li v-if="connected">\s*<button @click.stop.prevent="logout">[\s\S]*?<\/li>\n/, ""));
edit("src/components/header.vue", s => s.replace(/<a href="https:\/\/github.com\/m1k1o\/neko"[\s\S]*?<\/a>/, '<div class="neko"></div>'));
edit("src/components/about.vue", s => s.replace(/<img src="@\/assets\/images\/logo.svg"[^>]*>\s*<span><b>N<\/b>\.EKO<\/span>/, ""));
edit("public/site.webmanifest", s => s.replace(/"(name|short_name)": "n\.eko"/g, '"$1": "Browser"'));
edit("public/index.html", s => s
  .replace(/<title>[^<]*<\/title>/, "<title>Browser</title>")
  .replace(/n\.eko/g, "this page")
  .replace(/<link rel="(apple-touch-icon|icon|manifest|mask-icon)"[^>]*>\s*/g, "")
  .replace(/<meta name="(msapplication-TileColor|theme-color)"[^>]*>\s*/g, "")
  .replace(/<\/head>/, '<link rel="icon" href="favicon.svg"></head>')
  .replace(/<p>\s*A self hosted virtual browser[\s\S]*?<\/p>\s*/, ""));
writeFileSync(join(root, "src/assets/images/logo.svg"), '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>\n');
writeFileSync(join(root, "public/favicon.svg"), readFileSync(new URL("./favicon.svg", import.meta.url)));
console.log("client neutralized");
