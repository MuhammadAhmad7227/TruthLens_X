import http from "k6/http";
import { check, sleep } from "k6";
export const options = { vus: 100, duration: "30s" };
export default function () {
  const res = http.get(__ENV.TARGET_URL || "http://localhost:8000/healthz");
  check(res, { "health endpoint responds": r => r.status === 200 });
  sleep(1);
}
