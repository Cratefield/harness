// The smallest declaration of `bun:test` these tests use, and nothing more.
// The full types ship as `bun-types`; that is a third devDependency for
// editor comfort only — `bun test` itself needs nothing installed, so the
// package.json stays at the two dependencies the README names.
declare module "bun:test" {
	export interface Expectation {
		toBe(expected: unknown): Expectation;
		toEqual(expected: unknown): Expectation;
		toBeTruthy(): Expectation;
		toBeNull(): Expectation;
		toBeLessThan(expected: number): Expectation;
		toBeLessThanOrEqual(expected: number): Expectation;
		toHaveProperty(name: string, value?: unknown): Expectation;
		toMatch(pattern: RegExp): Expectation;
	}
	export function expect(actual: unknown): Expectation;
	export function describe(name: string, fn: () => void): void;
	export function it(name: string, fn: () => unknown | Promise<unknown>): void;
}
