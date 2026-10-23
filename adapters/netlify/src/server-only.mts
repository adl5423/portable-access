if (typeof globalThis.window !== "undefined" || typeof globalThis.document !== "undefined") {
  throw new Error("Portable Access must run on the server");
}

export {};
