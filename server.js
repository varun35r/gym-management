const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── DATABASE ──────────────────────────────────────────────
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) { console.log('❌ DB Error:', err.message); return; }
  console.log('✅ Connected to MySQL!');
});

// ── EMAIL SETUP ───────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ── MEMBERSHIP PRICES ─────────────────────────────────────
const MEMBERSHIPS = {
  'Day Pass':  { price: 500,   duration: '1 Day' },
  'Monthly':   { price: 3000,  duration: '1 Month' },
  '6 Months':  { price: 8000,  duration: '6 Months' },
  'Annual':    { price: 12000, duration: '1 Year' }
};

app.get('/api/memberships', (req, res) => res.json(MEMBERSHIPS));

// ── AUTH MIDDLEWARE ───────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

// ── REGISTER ─────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, email, phone, membership_type, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Fill all fields' });

  db.query('SELECT id FROM members WHERE email = ?', [email], async (err, rows) => {
    if (rows.length > 0) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    const sql = `INSERT INTO members (name, email, phone, membership_type, password, otp, otp_expires, role, email_verified)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'user', FALSE)`;
    db.query(sql, [name, email, phone, membership_type, hashed, otp, expires], async (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: '💪 GymPro — Your OTP Code',
        html: `
          <div style="font-family:sans-serif;max-width:400px;margin:auto;padding:24px;background:#1a1a2e;border-radius:12px;color:#fff;">
            <h2 style="color:#e94560;">💪 GymPro</h2>
            <p>Welcome <strong>${name}</strong>! Your OTP to verify your account is:</p>
            <h1 style="text-align:center;letter-spacing:8px;color:#e94560;font-size:40px;">${otp}</h1>
            <p style="color:#aaa;font-size:12px;">This OTP expires in 10 minutes. Do not share it with anyone.</p>
          </div>
        `
      });

      res.json({ message: 'OTP sent to your email!', id: result.insertId });
    });
  });
});

// ── VERIFY OTP ────────────────────────────────────────────
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  db.query('SELECT * FROM members WHERE email = ?', [email], (err, rows) => {
    if (rows.length === 0) return res.status(400).json({ error: 'User not found' });
    const user = rows[0];
    if (user.otp !== otp) return res.status(400).json({ error: 'Wrong OTP' });
    if (new Date() > new Date(user.otp_expires)) return res.status(400).json({ error: 'OTP expired' });
    db.query('UPDATE members SET email_verified = TRUE, otp = NULL WHERE email = ?', [email], () => {
      res.json({ message: '✅ Email verified! You can now login.' });
    });
  });
});

// ── LOGIN ─────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM members WHERE email = ?', [email], async (err, rows) => {
    if (rows.length === 0) return res.status(400).json({ error: 'Email not found' });
    const user = rows[0];
    if (!user.email_verified) return res.status(400).json({ error: 'Please verify your email first' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, name: user.name, id: user.id });
  });
});

// ── MEMBERS (admin only) ──────────────────────────────────
app.get('/api/members', authMiddleware, adminOnly, (req, res) => {
  db.query('SELECT id, name, email, phone, membership_type, join_date, role, email_verified FROM members', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.delete('/api/members/:id', authMiddleware, adminOnly, (req, res) => {
  db.query('DELETE FROM members WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '✅ Member deleted!' });
  });
});

// ── MY PROFILE (user) ─────────────────────────────────────
app.get('/api/my-profile', authMiddleware, (req, res) => {
  db.query('SELECT id, name, email, phone, membership_type, join_date FROM members WHERE id = ?', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows[0]);
  });
});

// ── ATTENDANCE ────────────────────────────────────────────
app.post('/api/checkin', authMiddleware, (req, res) => {
  const member_id = req.user.role === 'admin' ? req.body.member_id : req.user.id;
  db.query('INSERT INTO attendance (member_id) VALUES (?)', [member_id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '✅ Checked in!' });
  });
});

app.get('/api/attendance', authMiddleware, (req, res) => {
  let sql, params;
  if (req.user.role === 'admin') {
    sql = `SELECT attendance.id, members.name, attendance.checkin_time FROM attendance JOIN members ON attendance.member_id = members.id ORDER BY attendance.checkin_time DESC`;
    params = [];
  } else {
    sql = `SELECT attendance.id, members.name, attendance.checkin_time FROM attendance JOIN members ON attendance.member_id = members.id WHERE attendance.member_id = ? ORDER BY attendance.checkin_time DESC`;
    params = [req.user.id];
  }
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ── PT BOOKINGS ───────────────────────────────────────────
app.post('/api/bookings', authMiddleware, (req, res) => {
  const member_id = req.user.id;
  const { trainer_name, session_date, session_time } = req.body;
  db.query('INSERT INTO pt_bookings (member_id, trainer_name, session_date, session_time) VALUES (?, ?, ?, ?)',
    [member_id, trainer_name, session_date, session_time], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: '✅ PT session booked!' });
    });
});

app.get('/api/bookings', authMiddleware, (req, res) => {
  let sql, params;
  if (req.user.role === 'admin') {
    sql = `SELECT pt_bookings.*, members.name FROM pt_bookings JOIN members ON pt_bookings.member_id = members.id ORDER BY session_date DESC`;
    params = [];
  } else {
    sql = `SELECT pt_bookings.*, members.name FROM pt_bookings JOIN members ON pt_bookings.member_id = members.id WHERE pt_bookings.member_id = ? ORDER BY session_date DESC`;
    params = [req.user.id];
  }
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ── PROGRESS ──────────────────────────────────────────────
app.post('/api/progress', authMiddleware, (req, res) => {
  const member_id = req.user.id;
  const { weight_kg, body_fat, notes } = req.body;
  db.query('INSERT INTO progress (member_id, weight_kg, body_fat, notes) VALUES (?, ?, ?, ?)',
    [member_id, weight_kg, body_fat, notes], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: '✅ Progress saved!' });
    });
});

app.get('/api/progress/:member_id', authMiddleware, (req, res) => {
  const id = req.user.role === 'admin' ? req.params.member_id : req.user.id;
  db.query('SELECT * FROM progress WHERE member_id = ? ORDER BY recorded_date DESC', [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ── AI DIET PLAN ──────────────────────────────────────────
app.post('/api/diet-plan', authMiddleware, async (req, res) => {
  const member_id = req.user.id;
  const { goal_type, weight, height, age } = req.body;
  const prompt = `Create a detailed 7-day Indian diet plan for someone who wants to ${goal_type}. Weight: ${weight}kg, Height: ${height}cm, Age: ${age}. Include breakfast, lunch, dinner and snacks. Focus on affordable Indian foods. Include daily calorie and protein targets.`;
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + process.env.GROQ_API_KEY
  },
  body: JSON.stringify({
    model: 'llama-3.3-70b-versatile',
    max_tokens: 1500,
    messages: [{ role: 'user', content: prompt }]
  })
});
const data = await response.json();
console.log('AI Response:', JSON.stringify(data));
if (!data.choices || !data.choices[0]) {
  return res.status(500).json({ error: 'AI service error: ' + JSON.stringify(data) });
}
const planText = data.choices[0].message.content;

    // Save to database
    const sql = 'INSERT INTO diet_plans (member_id, goal_type, plan_text) VALUES (?, ?, ?)';
    res.json({ plan: planText });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AI WORKOUT PLAN ───────────────────────────────────────
app.post('/api/workout-plan', authMiddleware, async (req, res) => {
  const member_id = req.user.id;
  const { fitness_level, goal_type, days_per_week } = req.body;
  const prompt = `Create a detailed ${days_per_week}-day per week workout plan for a ${fitness_level} level person. Goal: ${goal_type}. Include exercises, sets, reps, rest time, warm-up and cool-down.`;
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + process.env.GROQ_API_KEY
  },
  body: JSON.stringify({
    model: 'llama-3.3-70b-versatile',
    max_tokens: 1500,
    messages: [{ role: 'user', content: prompt }]
  })
});
const data = await response.json();
console.log('AI Response:', JSON.stringify(data));
if (!data.choices || !data.choices[0]) {
  return res.status(500).json({ error: 'AI service error: ' + JSON.stringify(data) });
}
const planText = data.choices[0].message.content;

    const sql = 'INSERT INTO workout_plans (member_id, fitness_level, plan_text) VALUES (?, ?, ?)';
    res.json({ plan: planText });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── TRAINERS ──────────────────────────────────────────────
app.get('/api/trainers', authMiddleware, (req, res) => {
  const trainers = [
    { id: 1, name: 'Ravi Shankar', age: 34, qualification: 'B.Sc Sports Science, ISSA Certified', experience: '10 years', specialization: 'Strength & Powerlifting', rating: 4.9, available: ['Mon','Wed','Fri'] },
    { id: 2, name: 'Anjali Menon', age: 29, qualification: 'M.Sc Nutrition & Fitness, ACE Certified', experience: '6 years', specialization: 'Weight Loss & Cardio', rating: 4.8, available: ['Tue','Thu','Sat'] },
    { id: 3, name: 'Suresh Kumar', age: 38, qualification: 'B.P.Ed, NSCA-CSCS Certified', experience: '14 years', specialization: 'Muscle Building & Hypertrophy', rating: 4.7, available: ['Mon','Tue','Thu'] },
    { id: 4, name: 'Meera Nair', age: 31, qualification: 'B.Sc Physical Education, Yoga Certified', experience: '8 years', specialization: 'Flexibility, Yoga & Rehab', rating: 4.9, available: ['Wed','Fri','Sat'] },
    { id: 5, name: 'Arjun Reddy', age: 27, qualification: 'ACSM Certified, Sports Nutrition Diploma', experience: '4 years', specialization: 'Functional Training & Calisthenics', rating: 4.6, available: ['Mon','Wed','Sat'] }
  ];
  res.json(trainers);
});

// ── DASHBOARD STATS (admin) ───────────────────────────────
app.get('/api/stats', authMiddleware, adminOnly, (req, res) => {
  const queries = {
    members: 'SELECT COUNT(*) as count FROM members WHERE role = "user"',
    checkins: 'SELECT COUNT(*) as count FROM attendance',
    bookings: 'SELECT COUNT(*) as count FROM pt_bookings',
    today: 'SELECT COUNT(*) as count FROM attendance WHERE DATE(checkin_time) = CURDATE()'
  };
  const results = {};
  let done = 0;
  Object.entries(queries).forEach(([key, sql]) => {
    db.query(sql, (err, rows) => {
      results[key] = rows[0].count;
      if (++done === 4) res.json(results);
    });
  });
});

const PORT = process.env.PORT || 3000;
// ── GET MEMBER PLAN STATUS ────────────────────────────────
app.get('/api/plan-status', authMiddleware, (req, res) => {
  db.query('SELECT membership_type, plan_start_date, plan_end_date FROM members WHERE id = ?', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const member = rows[0];
    const today = new Date();
    const endDate = new Date(member.plan_end_date);
    const daysLeft = Math.ceil((endDate - today) / (1000 * 60 * 60 * 24));
    res.json({
      membership_type: member.membership_type,
      plan_start_date: member.plan_start_date,
      plan_end_date: member.plan_end_date,
      days_left: daysLeft,
      expired: daysLeft < 0,
      expiring_soon: daysLeft <= 7 && daysLeft >= 0
    });
  });
});

// ── RENEW / UPGRADE / CHANGE PLAN ────────────────────────
app.post('/api/change-plan', authMiddleware, (req, res) => {
  const { membership_type } = req.body;
  const validPlans = ['Day Pass', 'Monthly', '6 Months', 'Annual'];
  if (!validPlans.includes(membership_type)) return res.status(400).json({ error: 'Invalid plan' });

  const durations = {
    'Day Pass': 'INTERVAL 1 DAY',
    'Monthly': 'INTERVAL 1 MONTH',
    '6 Months': 'INTERVAL 6 MONTH',
    'Annual': 'INTERVAL 1 YEAR'
  };

  const sql = `UPDATE members SET 
    membership_type = ?, 
    plan_start_date = CURDATE(),
    plan_end_date = DATE_ADD(CURDATE(), ${durations[membership_type]})
    WHERE id = ?`;

  db.query(sql, [membership_type, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '✅ Plan updated successfully!' });
  });
});

// ── ADMIN: GET ALL MEMBERS WITH PLAN STATUS ───────────────
app.get('/api/members-status', authMiddleware, adminOnly, (req, res) => {
  const sql = `SELECT id, name, email, phone, membership_type, join_date, role, email_verified,
    plan_start_date, plan_end_date,
    DATEDIFF(plan_end_date, CURDATE()) as days_left
    FROM members WHERE role = 'user'`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));