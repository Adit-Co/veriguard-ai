type JsonWebKey = import('crypto').webcrypto.JsonWebKey

type ExportedHandlerEnv = unknown

type ExportedHandler<E = ExportedHandlerEnv> = {
  fetch?: (
    request: Request,
    env: E,
    ctx?: unknown,
  ) => Response | Promise<Response>
}
