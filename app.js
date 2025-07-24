const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const csrf = require('csurf');
const { body, sanitizeBody, validationResult } = require('express-validator');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const app = express();

// Base de données SQLite
const db = new sqlite3.Database(':memory:');

// Créer une table users (en mémoire pour l'exemple)
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT INTO users (username, password) VALUES ('alice', '1234'), ('bob', 'abcd')");
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
  secret: 'super-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, 
    sameSite: 'lax'
  }
}));
app.use(csrf({ cookie: false }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

let messages = [];

// Middleware : vérifie que l'utilisateur est connecté
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

app.get('/', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

// LOGIN sécurisé avec requête préparée
app.post('/login', 
  body('username').escape(),
  body('password').escape(),
  (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
      if (user) {
        req.session.user = user;
        res.redirect('/dashboard');
      } else {
        res.send('Échec de connexion');
      }
    });
  }
);

// CONTACT avec nettoyage contre XSS
app.get('/contact', (req, res) => {
  res.render('contact', { messages, csrfToken: req.csrfToken() });
});

app.post('/contact',
  body('message').trim().escape(),
  (req, res) => {
    const sanitizedMessage = req.body.message;
    messages.push(sanitizedMessage);
    res.redirect('/contact');
  }
);

// DASHBOARD sécurisé (IDOR)
app.get('/dashboard', requireAuth, (req, res) => {
  const userId = parseInt(req.query.id || req.session.user.id);
  // Empêche l'accès à d'autres profils
  if (userId !== req.session.user.id) return res.status(403).send('Accès interdit');
  res.render('dashboard', { user: req.session.user });
});

// MODIFICATION DE PROFIL (CSRF + Auth)
app.get('/edit-profile', requireAuth, (req, res) => {
  res.render('edit', { csrfToken: req.csrfToken() });
});

app.post('/edit-profile', requireAuth,
  body('username').trim().escape(),
  (req, res) => {
    req.session.user.username = req.body.username;
    res.redirect('/dashboard');
  }
);

// Serveur
app.listen(3000, () => {
  console.log('Mini-projet vulnérable en cours sur http://localhost:3000');
});
