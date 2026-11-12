import http from 'k6/http';
import { check } from 'k6';

const vusText = __ENV.VUS ?? '2';
const vus = Number(vusText);
if (!/^[1-9][0-9]*$/.test(vusText) || !Number.isSafeInteger(vus)) {
  throw new TypeError('VUS must be a positive decimal safe integer');
}

const p95Text = __ENV.P95_MS ?? '1000';
const failureText = __ENV.FAILURE_RATE ?? '0.01';
const decimal = /^(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)$/;
const p95Ms = Number(p95Text);
const failureRate = Number(failureText);
if (!decimal.test(p95Text) || !Number.isFinite(p95Ms) || p95Ms <= 0) {
  throw new TypeError('P95_MS must be a finite positive decimal number');
}
if (!decimal.test(failureText) || !Number.isFinite(failureRate)
    || failureRate < 0 || failureRate > 1) {
  throw new TypeError('FAILURE_RATE must be a decimal number between 0 and 1');
}

const url = __ENV.URL ?? 'https://localhost:8443/';
if (!/^https:\/\/[^\s/?#]+(?:[/?#][^\s]*)?$/.test(url)) {
  throw new TypeError('URL must be an absolute HTTPS URL');
}

const tlsVersion = __ENV.TLS_VERSION ?? 'tls1.3';
let expectedTls;
switch (tlsVersion) {
  case 'tls1.3':
    expectedTls = http.TLS_1_3;
    break;
  case 'tls1.2':
    expectedTls = http.TLS_1_2;
    break;
  default:
    throw new TypeError('TLS_VERSION must be tls1.3 or tls1.2');
}

const insecureText = __ENV.INSECURE_SKIP_TLS_VERIFY ?? 'true';
if (insecureText !== 'true' && insecureText !== 'false') {
  throw new TypeError('INSECURE_SKIP_TLS_VERIFY must be true or false');
}

const reuseText = __ENV.CONNECTION_REUSE ?? 'true';
if (reuseText !== 'true' && reuseText !== 'false') {
  throw new TypeError('CONNECTION_REUSE must be true or false');
}
const reuse = reuseText === 'true';

// vus + duration use k6's constant-vus shortcut and retain CLI option precedence.
export const options = {
  vus,
  duration: __ENV.DURATION ?? '30s',
  tlsVersion: { min: tlsVersion, max: tlsVersion },
  insecureSkipTLSVerify: insecureText === 'true',
  noConnectionReuse: !reuse,
  maxRedirects: 0,
  summaryTrendStats: ['avg', 'min', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
  thresholds: {
    checks: ['rate==1'],
    // http_req_failed: [`rate<${failureRate}`],
    // http_req_duration: [`p(95)<${p95Ms}`],
    // http_req_tls_handshaking: [`p(95)<${p95Ms}`],
  },
};

export default function () {
  const response = http.get(url, { timeout: '10s', redirects: 0 });
  check(response, {
    'status is 200': (r) => r.status === 200,
    'body matches exactly': (r) => r.body === 'Hello from the TEE!\n',
    'TLS version matches': (r) => r.tls_version === expectedTls,
  });
}
