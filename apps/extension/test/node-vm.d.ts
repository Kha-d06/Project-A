// The two node:vm functions the self-containment test uses (the extension has no Node types).
declare module "node:vm" {
  export function createContext(sandbox: object): object;
  export function runInContext(code: string, context: object): unknown;
  const vm: { createContext: typeof createContext; runInContext: typeof runInContext };
  export default vm;
}
