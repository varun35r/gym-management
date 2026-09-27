const bcrypt = require('bcryptjs');

async function generate() {
  const hash = await bcrypt.hash('admin123', 10);
  console.log('Your hashed password:', hash);
}

generate();