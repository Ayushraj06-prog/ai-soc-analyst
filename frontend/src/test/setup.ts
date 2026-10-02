import '@testing-library/jest-dom/vitest'

// Node 25 exposes a global localStorage shim that can shadow jsdom's storage.
// Keep tests on a deterministic browser-like Storage implementation.
function createStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key) => values.get(String(key)) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(String(key)) },
    setItem: (key, value) => { values.set(String(key), String(value)) },
  }
}

Object.defineProperty(window, 'localStorage', { configurable: true, value: createStorage() })
Object.defineProperty(window, 'sessionStorage', { configurable: true, value: createStorage() })

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
})
