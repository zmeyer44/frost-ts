module.exports = {
  preset: "ts-jest",
  collectCoverageFrom: ["src/**/*.ts"],
  modulePathIgnorePatterns: ["examples/.*", "website/.*"],
  testPathIgnorePatterns: ["src/__mocks__/*", "<rootDir>/node_modules/"],
  globals: {
    "ts-jest": {
      tsconfig: "tsconfig.jest.json",
    },
  },
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
};
