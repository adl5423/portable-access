import type { Config } from "@netlify/functions";
import { NO_CACHE } from "../../src/protocol.mjs";
export default () => new Response('{"ok":true}', { status: 200, headers: { ...NO_CACHE, "Content-Type": "application/json" } });
export const config: Config = { path: "/health", method: "GET" };
