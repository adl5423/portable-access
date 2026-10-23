import "./server-only.mjs";
import type { DeploySucceededEvent } from "@netlify/functions";
import { BackgroundRecordsReader, type BackgroundReadClient, type BackgroundReadOptions } from "./background.mjs";
import { AccessError, assertPlatform, validateConfig, type PlatformContext, type PublicConfig } from "./protocol.mjs";

export interface DeployCheckReport {
  event: "pap.deploy-check";
  outcome: "skipped" | "passed" | "failed";
  stage: "disabled" | "context" | "initial-read" | "second-read";
  code: string;
  records_count?: number;
}

export interface DeployCheckOptions {
  context: () => PlatformContext;
  client?: (config: PublicConfig) => BackgroundReadClient;
  background?: Omit<BackgroundReadOptions, "client">;
  pause?: (milliseconds: number) => Promise<void>;
  report: (report: DeployCheckReport) => void;
}

const safeCodes = new Set(["adapter_not_configured", "untrusted_deployment", "event_binding_mismatch", "context_unavailable", "access_denied", "issuer_unavailable", "resource_unavailable", "invalid_records_response", "client_closed", "background_read_aborted", "background_read_deadline"]);

/** Only Netlify's verified deploy event calls this fixed, read-only acceptance operation. */
export function createDeployCheck(publicConfig: unknown, options: DeployCheckOptions) {
  return async (event: DeploySucceededEvent): Promise<void> => {
    if (typeof publicConfig === "object" && publicConfig !== null && "enabled" in publicConfig && publicConfig.enabled === false) {
      options.report({ event: "pap.deploy-check", outcome: "skipped", stage: "disabled", code: "adapter_not_configured" });
      return;
    }
    let stage: DeployCheckReport["stage"] = "context";
    let client: BackgroundRecordsReader | undefined;
    try {
      const config = validateConfig(publicConfig);
      let context: PlatformContext;
      try { context = options.context(); } catch { throw new AccessError("context_unavailable", 503); }
      assertPlatform(config, context);
      if (event?.site?.id !== config.siteID || event?.deploy?.siteId !== config.siteID || event?.deploy?.context !== "production" || !event.deploy.publishedAt) {
        throw new AccessError("event_binding_mismatch", 403);
      }
      client = new BackgroundRecordsReader(config, { ...options.background, ...(options.client ? { client: options.client } : {}) });
      stage = "initial-read";
      const first = await client.readRecords(context);
      options.report({ event: "pap.deploy-check", outcome: "passed", stage, code: "operation_succeeded", records_count: first.records.length });
      // With the acceptance issuer's 60-second TTL, the second operation requires renewal.
      // Authority audit evidence, rather than this log alone, establishes that renewal occurred.
      await (options.pause?.(65_000) ?? new Promise((resolve) => setTimeout(resolve, 65_000)));
      stage = "second-read";
      const second = await client.readRecords(context);
      options.report({ event: "pap.deploy-check", outcome: "passed", stage, code: "operation_succeeded", records_count: second.records.length });
    } catch (error) {
      const code = error instanceof AccessError && safeCodes.has(error.code) ? error.code : "operation_failed";
      options.report({ event: "pap.deploy-check", outcome: "failed", stage, code });
    } finally {
      client?.close();
    }
  };
}
