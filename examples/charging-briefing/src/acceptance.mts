import type { DeploySucceededEvent } from "@netlify/functions";
import { PortableAccessClient } from "@portable-access/netlify";
import { AccessError, assertPlatform, validateConfig, type PlatformContext, type PublicConfig } from "@portable-access/netlify/protocol";
import { parseBriefing, type Briefing, type Operation } from "./relay.mjs";

export interface AcceptanceClient { getJSON(context: PlatformContext): Promise<unknown>; close(): void }
export interface AcceptanceReport {
  event: "pap.example.acceptance"; operation: Operation;
  outcome: "skipped" | "passed" | "failed";
  stage: "disabled" | "context" | "initial-read" | "second-read"; code: string;
}
export interface AcceptanceOptions {
  context: () => PlatformContext;
  client?: (policy: PublicConfig) => AcceptanceClient;
  pause?: (milliseconds: number) => Promise<void>;
  publish: (briefing: Briefing) => Promise<void>;
  report: (report: AcceptanceReport) => void;
}

/** Invoked only by Netlify's verified platform event, never by an HTTP handler. */
export function createDeployAcceptance(publicConfig: unknown, operation: Operation, options: AcceptanceOptions) {
  return async (event: DeploySucceededEvent): Promise<void> => {
    if (typeof publicConfig === "object" && publicConfig !== null && "enabled" in publicConfig && publicConfig.enabled === false) {
      options.report({ event: "pap.example.acceptance", operation, outcome: "skipped", stage: "disabled", code: "adapter_not_configured" });
      return;
    }
    let stage: AcceptanceReport["stage"] = "context";
    let client: AcceptanceClient | undefined;
    try {
      const policy = validateConfig(publicConfig);
      const context = options.context();
      assertPlatform(policy, context);
      if (event?.site?.id !== policy.siteID || event?.deploy?.siteId !== policy.siteID || event?.deploy?.context !== "production" || !event.deploy.publishedAt) throw new AccessError("event_binding_mismatch", 403);
      client = options.client?.(policy) ?? new PortableAccessClient(policy);
      stage = "initial-read";
      const first = parseBriefing(await client.getJSON(context), operation);
      await options.publish(first);
      options.report({ event: "pap.example.acceptance", operation, outcome: "passed", stage, code: "operation_succeeded" });
      await (options.pause?.(65000) ?? new Promise((resolve) => setTimeout(resolve, 65000)));
      stage = "second-read";
      const second = parseBriefing(await client.getJSON(context), operation);
      await options.publish(second);
      options.report({ event: "pap.example.acceptance", operation, outcome: "passed", stage, code: "operation_succeeded" });
    } catch (error) {
      const allowed = new Set(["adapter_not_configured", "untrusted_deployment", "event_binding_mismatch", "access_denied", "issuer_unavailable", "resource_unavailable", "invalid_briefing"]);
      options.report({ event: "pap.example.acceptance", operation, outcome: "failed", stage, code: error instanceof AccessError && allowed.has(error.code) ? error.code : "operation_failed" });
    } finally { client?.close(); }
  };
}
