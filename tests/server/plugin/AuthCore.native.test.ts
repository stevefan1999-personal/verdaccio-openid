import { Auth, getMiddlewareCredentials } from "@verdaccio/auth";
import type { Config, Logger, Security } from "@verdaccio/types";

import ParsedPluginConfig from "@/server/config/Config";
import { AuthCore } from "@/server/plugin/AuthCore";
import type { AuthProvider } from "@/server/plugin/AuthProvider";

const now = new Date("2026-01-01T00:00:00Z");
const millisecondsPerSecond = 1000;
const issuedAt = now.getTime() / millisecondsPerSecond;
const tokenLifetime = 60;
const defaultUiLifetime = 60 * 60;
const secret = "s".repeat(32);
const anonymous = { name: undefined, real_groups: [], groups: ["$all", "$anonymous", "@all", "@anonymous"] };
const logger = {
  child: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as Logger;
const provider: AuthProvider = {
  getId: () => "test-provider",
  getLoginUrl: vi.fn(),
  getToken: vi.fn(),
  getUserinfo: vi.fn(),
};
const jwtSecurity: Security = {
  web: { sign: { expiresIn: tokenLifetime } },
  api: {
    legacy: false,
    jwt: {
      sign: { expiresIn: tokenLifetime, audience: "registry", issuer: "plugin", algorithm: "HS256" },
      verify: { audience: "registry", issuer: "plugin", algorithms: ["HS256"] },
    },
  },
};

function createCore(security: Partial<Security> = {}, signingSecret = secret) {
  const config = { secret: signingSecret, security, packages: {} } as Config;
  const parsed = new ParsedPluginConfig({ "provider-host": "https://provider.test" }, config);
  const core = new AuthCore(parsed, provider);
  core.setAuth(new Auth({ ...config, security: parsed.security }, logger));
  return core;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(now);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("AuthCore with native Verdaccio helpers", () => {
  it("signs and verifies npm tokens with the configured options and groups", async () => {
    const core = createCore(jwtSecurity);
    const token = await core.issueNpmToken("reader", ["registry-user"], "unused-provider-token");

    expect(await core.verifyNpmToken(token)).toEqual({
      name: "reader",
      real_groups: ["registry-user"],
      groups: ["registry-user", "$all", "$authenticated", "@all", "@authenticated", "all"],
      iat: issuedAt,
      exp: issuedAt + tokenLifetime,
      aud: "registry",
      iss: "plugin",
    });
  });

  it("keeps the default one-hour UI token lifetime", async () => {
    const core = createCore();
    const token = await core.issueUiToken("reader", ["registry-user"]);

    expect(core.verifyUiToken(token)).toMatchObject({
      name: "reader",
      iat: issuedAt,
      exp: issuedAt + defaultUiLifetime,
    });
  });

  it("refuses npm tokens at their expiry boundary", async () => {
    const core = createCore(jwtSecurity);
    const token = await core.issueNpmToken("reader", ["registry-user"], "unused-provider-token");

    vi.setSystemTime(now.getTime() + (tokenLifetime - 1) * millisecondsPerSecond);
    expect(await core.verifyNpmToken(token)).toHaveProperty("name", "reader");
    vi.setSystemTime(now.getTime() + tokenLifetime * millisecondsPerSecond);
    expect(await core.verifyNpmToken(token)).toEqual(anonymous);
  });

  it("refuses a token signed with a different secret", async () => {
    const token = await createCore(jwtSecurity, "x".repeat(32)).issueNpmToken("reader", ["registry-user"], "unused");

    expect(await createCore(jwtSecurity).verifyNpmToken(token)).toEqual(anonymous);
  });

  it.each([{ audience: "other-registry" }, { issuer: "other-plugin" }, { algorithm: "HS512" as const }])(
    "refuses a token with mismatched verification options %j",
    async (sign) => {
      const signer = createCore({
        ...jwtSecurity,
        api: { jwt: { sign: { ...jwtSecurity.api.jwt!.sign, ...sign } } },
      });
      const token = await signer.issueNpmToken("reader", ["registry-user"], "unused");

      expect(await createCore(jwtSecurity).verifyNpmToken(token)).toEqual(anonymous);
    },
  );

  it("keeps the legacy token envelope compatible with Verdaccio authentication", async () => {
    const core = createCore();
    const token = await core.issueNpmToken("reader", ["registry-user"], {
      accessToken: "unused-provider-token",
      expiresAt: issuedAt + tokenLifetime,
    });
    const security = new ParsedPluginConfig({ "provider-host": "https://provider.test" }, { secret } as Config)
      .security;
    const credentials = getMiddlewareCredentials(security, secret, `Bearer ${token}`);

    expect(credentials).toHaveProperty("user", "reader");
    if (!credentials || !("password" in credentials)) throw new Error("Expected the native legacy token envelope");
    expect(await core.verifyNpmToken(credentials.password)).toEqual({ name: "reader", real_groups: ["registry-user"] });
  });
});
