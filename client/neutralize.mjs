// Strip the neko name and logo from the client before it is built, so the viewer carries no brand.
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
edit("src/components/unsupported.vue", s => s.replace(logoBlock, ""));
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
