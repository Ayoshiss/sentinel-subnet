# dcap-qvl for the browser

`dcap-qvl-0.7.0.js` is Phala's [dcap-qvl](https://github.com/Phala-Network/dcap-qvl)
JavaScript package, version 0.7.0 (Apache-2.0), bundled for the browser with
its dependencies. It checks Intel's signature on a TDX quote, the same job the
validator gives the Python build of the same library.

Rebuild it and compare:

```bash
mkdir qvl && cd qvl && npm init -y
npm install --ignore-scripts @phala/dcap-qvl@0.7.0 buffer@6.0.3 esbuild@0.24.0
cat > entry.js <<'JS'
import { Buffer } from "buffer";
globalThis.Buffer = globalThis.Buffer || Buffer;
const qvl = require("@phala/dcap-qvl");
export const getCollateral = qvl.getCollateral;
export const verify = qvl.verify;
export const PHALA_PCCS_URL = qvl.PHALA_PCCS_URL;
export { Buffer };
JS
./node_modules/.bin/esbuild entry.js --bundle --format=esm --platform=browser \
  --minify --legal-comments=inline --outfile=dcap-qvl-0.7.0.js
shasum -a 256 dcap-qvl-0.7.0.js
```

SHA-256 of the committed file: `dd061f7a57901fac91f75b333f72dd2d9b8f8804d020bf0fa0e62641944d6694`. Transitive versions come from npm at
install time, so a rebuild matches only while those resolve the same; the
package names and versions are in the bundle's legal comments.
