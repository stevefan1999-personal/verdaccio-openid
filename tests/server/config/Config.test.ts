import { defaultSecurity } from "@verdaccio/config";
import type { Config, Security } from "@verdaccio/types";

import ParsedPluginConfig from "@/server/config/Config";
import * as utils from "@/server/config/utils";
import { ProviderType } from "@/server/plugin/AuthProvider";
import { StoreType } from "@/server/store/Store";

const mockConfig = {
  "provider-host": "https://provider.test",
  "client-id": "test-client-id",
  "client-secret": "test-client-secret",
};

const mockVerdaccioConfig = {
  secret: "test-secret",
  security: {},
  packages: {},
  url_prefix: "/prefix",
  self_path: "/test/path",
} as Config;

describe("ParsedPluginConfig", () => {
  it("should return secret from verdaccio config", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.secret).toBe("test-secret");
  });

  it("should merge default security with verdaccio config", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.security).toEqual(defaultSecurity);
    expect(config.security).not.toBe(defaultSecurity);
  });

  it.each([undefined, null])("should use security defaults for absent input %s", (security) => {
    const config = new ParsedPluginConfig(mockConfig, {
      ...mockVerdaccioConfig,
      security,
    } as Config);

    expect(config.security).toEqual(defaultSecurity);
  });

  it("should preserve nested token options without mutating either input", () => {
    const security = {
      web: { sign: { expiresIn: "15m", audience: ["browser"] } },
      api: { legacy: false, jwt: { sign: { expiresIn: "10m" }, verify: { algorithms: ["HS256"] } } },
    } as Security;
    const originalSecurity = structuredClone(security);
    const originalDefaults = structuredClone(defaultSecurity);
    const config = new ParsedPluginConfig(mockConfig, { ...mockVerdaccioConfig, security });
    const result = config.security;

    expect(result).toEqual({
      web: { sign: { expiresIn: "15m", audience: ["browser"] }, verify: {} },
      api: {
        ...originalDefaults.api,
        legacy: false,
        jwt: { sign: { expiresIn: "10m" }, verify: { algorithms: ["HS256"] } },
      },
    });
    result.api.jwt!.verify!.algorithms!.push("HS512");
    result.web.sign.expiresIn = "1s";
    expect(security).toEqual(originalSecurity);
    expect(defaultSecurity).toEqual(originalDefaults);
    expect(config.security.api.jwt!.verify!.algorithms).toEqual(["HS256"]);
  });

  it("should concatenate token option arrays in order", () => {
    const originalVerify = defaultSecurity.web.verify;
    try {
      defaultSecurity.web.verify = { algorithms: ["HS256"] };
      const config = new ParsedPluginConfig(mockConfig, {
        ...mockVerdaccioConfig,
        security: { web: { verify: { algorithms: ["HS512"] } } },
      } as Config);

      expect(config.security.web.verify.algorithms).toEqual(["HS256", "HS512"]);
      expect(defaultSecurity.web.verify.algorithms).toEqual(["HS256"]);
    } finally {
      defaultSecurity.web.verify = originalVerify;
    }
  });

  it("should preserve enumerable symbols and clone their values", () => {
    const visible = Symbol("visible option");
    const hidden = Symbol("hidden option");
    const option = { audiences: ["browser"] };
    const security = Object.defineProperty({ [visible]: option }, hidden, { value: "hidden" });
    const config = new ParsedPluginConfig(mockConfig, { ...mockVerdaccioConfig, security } as Config);
    const result = config.security;

    expect(Reflect.get(result, visible)).toEqual(option);
    expect(Reflect.get(result, visible)).not.toBe(option);
    expect(Object.getOwnPropertySymbols(result)).toEqual([visible]);
  });

  it.each(["__proto__", "constructor", "prototype"])("should reject %s keys in merged and cloned objects", (key) => {
    const hostile = { [key]: { inheritedOption: true } };
    const security = {
      ...hostile,
      web: { sign: { ...hostile, expiresIn: "15m" } },
      api: { jwt: { verify: hostile } },
      extraOptions: [hostile],
    } as Security & { extraOptions: Record<string, unknown>[] };
    const config = new ParsedPluginConfig(mockConfig, { ...mockVerdaccioConfig, security });
    const result = config.security as typeof security;
    const objects = [result, result.web.sign, result.api.jwt!.verify!, result.extraOptions[0]];

    for (const object of objects) {
      expect(Object.getPrototypeOf(object)).toBe(Object.prototype);
      expect(Object.hasOwn(object, key)).toBe(false);
      expect(Reflect.get(object, "inheritedOption")).toBeUndefined();
    }
    expect(Object.prototype).not.toHaveProperty("inheritedOption");
    expect(result.web.sign.expiresIn).toBe("15m");
    expect(Object.hasOwn(security, key)).toBe(true);
  });

  it("should return packages from verdaccio config", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.packages).toEqual({});
  });

  it("should return url prefix from verdaccio config", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.urlPrefix).toBe("/prefix");
  });

  it("should get provider host from config", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.providerHost).toBe("https://provider.test");
  });

  it("should get optional provider type", () => {
    const configWithType = {
      ...mockConfig,
      "provider-type": ProviderType.Gitlab,
    };
    const config = new ParsedPluginConfig(configWithType, mockVerdaccioConfig);
    expect(config.providerType).toBe(ProviderType.Gitlab);
  });

  it("should get client credentials", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.clientId).toBe("test-client-id");
    expect(config.clientSecret).toBe("test-client-secret");
  });

  it("should get default scope if not specified", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.scope).toBe("openid");
  });

  it("should get default username claim if not specified", () => {
    const config = new ParsedPluginConfig(mockConfig, mockVerdaccioConfig);
    expect(config.usernameClaim).toBe("sub");
  });

  it("should get redis store config for redis store", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.Redis,
        "store-config": "redis://redis-host:1234/0",
      },
      mockVerdaccioConfig,
    );

    expect(config.storeType).toBe(StoreType.Redis);
    expect(config.getStoreConfig(StoreType.Redis)).toBe("redis://redis-host:1234/0");

    const config1 = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.Redis,
        "store-config": "rediss://redis-host:1234/0",
      },
      mockVerdaccioConfig,
    );

    expect(config1.getStoreConfig(StoreType.Redis)).toBe("rediss://redis-host:1234/0");

    const config2 = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.Redis,
        "store-config": {
          host: "redis-host",
          port: 1234,
          db: 0,
        },
      },
      mockVerdaccioConfig,
    );
    expect(config2.getStoreConfig(StoreType.Redis)).toEqual({
      host: "redis-host",
      port: 1234,
      db: 0,
    });
  });

  it("should get store config for in-memory store", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.InMemory,
      },
      mockVerdaccioConfig,
    );
    expect(config.storeType).toBe(StoreType.InMemory);
    expect(config.getStoreConfig(StoreType.InMemory)).toBeUndefined();
  });

  it("should handle environment variables", () => {
    vi.spyOn(utils, "getEnvironmentValue").mockReturnValue("env-value");
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "client-id": "$CLIENT_ID",
      },
      mockVerdaccioConfig,
    );
    expect(config.clientId).toBe("env-value");
  });
});

describe("Invalid ParsedPluginConfig", () => {
  beforeEach(() => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it("should throw error if provider host is not specified", () => {
    const config = new ParsedPluginConfig({} as any, mockVerdaccioConfig);

    expect(() => config.providerHost).toThrowError("process.exit called");
  });

  it("should throw error if client id is not specified", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "client-id": "",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.clientId).toThrowError("process.exit called");
  });

  it("should throw error if client secret is not specified", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "client-secret": "",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.clientSecret).toThrowError("process.exit called");
  });

  it("should throw error if provider type is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "provider-type": "invalid" as any,
      },
      mockVerdaccioConfig,
    );

    expect(() => config.providerType).toThrowError("process.exit called");
  });

  it("should throw error if configuration uri is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "configuration-uri": "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.configurationUri).toThrowError("process.exit called");
  });

  it("should throw error if issuer is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        issuer: "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.issuer).toThrowError("process.exit called");
  });

  it("should throw error if authorization endpoint is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "authorization-endpoint": "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.authorizationEndpoint).toThrowError("process.exit called");
  });

  it("should throw error if token endpoint is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "token-endpoint": "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.tokenEndpoint).toThrowError("process.exit called");
  });

  it("should throw error if userinfo endpoint is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "userinfo-endpoint": "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.userinfoEndpoint).toThrowError("process.exit called");
  });

  it("should throw error if jwks uri is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "jwks-uri": "invalid-uri",
      },
      mockVerdaccioConfig,
    );

    expect(() => config.jwksUri).toThrowError("process.exit called");
  });

  it("should throw error if store type is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": "invalid" as any,
      },
      mockVerdaccioConfig,
    );

    expect(() => config.storeType).toThrowError("process.exit called");
  });

  it("should throw error if store config is invalid", () => {
    const configInMemory = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.InMemory,
        "store-config": "invalid",
      },
      mockVerdaccioConfig,
    );

    expect(() => configInMemory.getStoreConfig(StoreType.InMemory)).toThrowError("process.exit called");

    const configRedis = new ParsedPluginConfig(
      {
        ...mockConfig,
        "store-type": StoreType.Redis,
        "store-config": "invalid",
      },
      mockVerdaccioConfig,
    );

    expect(() => configRedis.getStoreConfig(StoreType.Redis)).toThrowError("process.exit called");
  });

  it("should throw error if authorized groups is invalid", () => {
    const config = new ParsedPluginConfig(
      {
        ...mockConfig,
        "authorized-groups": 123 as any,
      },
      mockVerdaccioConfig,
    );

    expect(() => config.authorizedGroups).toThrowError("process.exit called");
  });
});
