// TypeScript: Class and inheritance issues
class Animal {
  name: string;

  constructor(name: string) {
    this.name = name;
  }

  // Unsafe: Protected member accessible from outside
  protected id: number = 0;
}

class Dog extends Animal {
  breed: string;

  constructor(name: string, breed: string) {
    super(name);
    this.breed = breed;
  }

  // Unsafe: Method modifying parent state
  changeName(newName: string) {
    this.name = newName; // Direct modification
  }
}

// Unsafe: Abstract class instantiation
abstract class Shape {
  abstract area(): number;

  describe() {
    return `Area: ${this.area()}`;
  }
}

// const shape = new Shape(); // Compilation error, but possible at runtime

// Unsafe: Mixin pattern type issues
type Constructor<T = {}> = new (...args: any[]) => T;

function Timestamped<TBase extends Constructor>(Base: TBase) {
  return class extends Base {
    createdAt = new Date();
    updatedAt = new Date();
  };
}

class BaseEntity {
  id: number = 0;
}

const TimestampedEntity = Timestamped(BaseEntity);
// Unsafe: No type safety for mixed properties

// TypeScript: Decorator type issues
function Log(target: any, propertyKey: string, descriptor: PropertyDescriptor) {
  const original = descriptor.value;
  descriptor.value = function (...args: any[]) {
    console.log(`Calling ${propertyKey} with`, args);
    return original.apply(this, args);
  };
}

class ApiService {
  @Log
  async fetchData(url: string): Promise<any> {
    // Unsafe: No error handling in decorator
    const response = await fetch(url);
    return response.json();
  }
}

// TypeScript: Mapped type issues
type Mutable<T> = {
  -readonly [P in keyof T]: T[P];
};

interface Config {
  readonly apiKey: string;
  readonly secret: string;
}

// Unsafe: Removing readonly allows mutation
function updateConfig(config: Mutable<Config>, updates: Partial<Config>) {
  Object.assign(config, updates); // Bypasses readonly
}

// TypeScript: Conditional type pitfalls
type IsString<T> = T extends string ? true : false;

function checkString<T>(value: T): IsString<T> {
  // Unsafe: Type assertion
  return (typeof value === 'string') as IsString<T>;
}

export { Dog, TimestampedEntity, ApiService, updateConfig, checkString };
