// Flat ESLint config. The load-bearing rule bans declaring a money / scaled
// field as a JS `number`: i64 Price/Quantity/Ratio must be `bigint` and i128
// Amount must be a decimal `string`. JS numbers silently lose precision past
// 2^53, so money must never cross as one.
import tseslint from "typescript-eslint";

const MONEY_FIELD =
  "^(price|quantity|tick_size|lot_size|mark_price|index_price|funding_rate|" +
  "open_interest|entry_price|unrealized_pnl|size|balance|equity|amount|filled|" +
  "notional|leverage|collateral|margin|fee|funding)$";

export default tseslint.config(
  { ignores: ["dist/**", "wasm/**", "node_modules/**", "scripts/**"] },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      sourceType: "module",
    },
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: `:matches(TSPropertySignature, TSPropertyDefinition)[key.name=/${MONEY_FIELD}/] TSNumberKeyword`,
          message:
            "Money/scaled fields must be bigint (i64 Price/Quantity/Ratio) or a decimal string (i128 Amount), never a JS number.",
        },
      ],
    },
  },
);
