interface User {
  id: number;
  name: string;
  email: string;
}

function processUser(user: User): string {
  // Type error: can't assign number to string
  const result: string = user.id;
  
  // Missing property
  const userAge = user.age;
  
  // Incorrect comparison
  if (user.id == '123') {
    return 'found';
  }
  
  return user.name;
}

// Unused parameter
function unusedParam(param: string): void {
  console.log('not using param');
}

// Never used function
function neverCalled(): number {
  return 42;
}

export { processUser };