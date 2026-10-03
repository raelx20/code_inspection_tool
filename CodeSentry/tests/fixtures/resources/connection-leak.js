// Memory leak: Unclosed database connections
const mysql = require('mysql2');

class UserService {
  constructor() {
    this.connection = mysql.createConnection({
      host: 'localhost',
      user: 'root',
      database: 'mydb'
    });
    // Connection never closed
  }

  async getUser(id) {
    return new Promise((resolve, reject) => {
      this.connection.query('SELECT * FROM users WHERE id = ?', [id], (err, rows) => {
        if (err) reject(err);
        else resolve(rows[0]);
      });
    });
  }

  // Connection pool leak: creating new connections without releasing
  async getUsers() {
    const conn = mysql.createConnection({...});
    const rows = await conn.promise().query('SELECT * FROM users');
    // Forgot to call conn.end() or release()
    return rows;
  }
}

// Memory leak: HTTP agent reuse without cleanup
const http = require('http');
const agent = new http.Agent({ keepAlive: true });

async function fetchData(url) {
  return new Promise((resolve, reject) => {
    http.get(url, { agent }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
  // Agent never destroyed, sockets accumulate
}

// Memory leak: WebSocket connections not closed
class WSManager {
  constructor() {
    this.clients = new Map();
  }

  addClient(id, ws) {
    this.clients.set(id, ws);
    ws.on('message', (msg) => this.handleMessage(id, msg));
    // Never remove closed connections
  }

  handleMessage(id, msg) {
    console.log(`Message from ${id}:`, msg);
  }
}

module.exports = { UserService, fetchData, WSManager };
