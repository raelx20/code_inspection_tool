// TypeScript: Type safety bypasses
interface User {
  id: number;
  name: string;
  email: string;
}

// Unsafe type assertion
function processUser(data: any): User {
  return data as User; // Bypasses type checking
}

// Unsafe null assertion
function getUserName(user: User | null): string {
  return user!.name; // Assumes user is not null
}

// Unsafe any usage
function processData(input: any): any {
  return input.someProperty.nestedProperty; // No type safety
}

// TypeScript: Generic type issues
function identity<T>(arg: T): T {
  return arg;
}

// Unsafe: Type widening
let value: string | number = 'hello';
value = 42; // Allowed but may be unintended

// Unsafe: Array covariance
const numbers: number[] = [1, 2, 3];
const anys: any[] = numbers; // Allows pushing strings
anys.push('hello'); // Runtime error potential

// TypeScript: Enum pitfalls
enum Status {
  Active = 'ACTIVE',
  Inactive = 'INACTIVE'
}

function processStatus(status: Status) {
  // Unsafe: Enum value can be any string at runtime
  if (status === 'ACTIVE') { // Comparison with string literal
    return true;
  }
  return false;
}

// Unsafe: Type guard bypass
function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function processValue(value: unknown) {
  if (isString(value)) {
    return value.toUpperCase(); // Safe
  }
  // Attacker can bypass this check
  return (value as string).toUpperCase(); // Unsafe
}

// TypeScript: Async/Promise type issues
async function fetchData(): Promise<string> {
  const response = await fetch('/api/data');
  // Missing error handling, promise rejection unhandled
  return response.json();
}

// Unsafe: Type assertion after async
async function processAsync(data: Promise<any>) {
  const result = await data;
  return result as User; // Unsafe assertion
}

export { processUser, getUserName, processData, processStatus, processValue, fetchData, processAsync };
