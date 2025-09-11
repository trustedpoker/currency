export type AuthDataProvider<T, Provider, Extra = unknown> = {
  type: T;
  provider: Provider;
} & Extra;
