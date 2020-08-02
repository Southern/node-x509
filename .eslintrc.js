module.exports = {
  env: {
    commonjs: true,
    es2020: true,
    node: true,
    jest: true
  },
  extends: [
    'plugin:import/recommended',
    'plugin:jest/all',
    'plugin:node/recommended',
    'plugin:promise/recommended',
    'standard'
  ],
  plugins: [
    'import',
    'jest',
    'node',
    'promise',
    'standard'
  ],
  parserOptions: {
    ecmaVersion: 11
  },
  rules: {
    'jest/no-test-callback': ['off'],
    semi: ['error', 'always']
  }
};
