require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const fs = require('fs');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Sesje
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 30 * 60 * 1000 } // 30 minut
}));

// Plik JSON jako baza
const dbFile = path.join(__dirname, 'clients.json');
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, JSON.stringify([]));
}

// Mapowanie planów i cen (w groszach)
const priceIds = {
  1: 'price_1S330PLlytmmOHVO4iIJ8Un6',
  2: 'price_1S3HBILlytmmOHVOng1Blntx',
  3: 'price_1S3HBeLlytmmOHVOsQiqiMXw'
};
const prices = {
  1: 5900, // 59 PLN
  2: 7900, // 79 PLN
  3: 9900  // 99 PLN
};

// Middleware uwierzytelniania
const authenticate = (req, res, next) => {
  if (req.session.loggedIn) {
    return next();
  }
  res.redirect('/admin/login.html');
};

// Domyślne dane admina
const adminPasswordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);

// Endpoint logowania
app.post('/admin/login', bodyParser.json(), (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && bcrypt.compareSync(password, adminPasswordHash)) {
    req.session.loggedIn = true;
    res.json({ success: true, redirect: '/admin/dashboard' });
  } else {
    res.status(401).json({ error: 'Błędny login lub hasło' });
  }
});

// Endpoint wylogowania
app.get('/admin/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin/login.html');
});

// Strona panelu admina
app.get('/admin/dashboard', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

// API: Pobierz wszystkie zamówienia
app.get('/api/clients', authenticate, (req, res) => {
  try {
    const clients = JSON.parse(fs.readFileSync(dbFile));
    res.json(clients);
  } catch (err) {
    console.error('Błąd odczytu clients.json:', err.message);
    res.status(500).json({ error: 'Błąd odczytu danych' });
  }
});

// API: Aktualizuj status zamówienia
app.post('/api/update-status', authenticate, bodyParser.json(), (req, res) => {
  const { id, status } = req.body;
  try {
    const clients = JSON.parse(fs.readFileSync(dbFile));
    const client = clients.find(c => c.id === id);
    if (client) {
      client.status = status;
      fs.writeFileSync(dbFile, JSON.stringify(clients, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Zamówienie nie znalezione' });
    }
  } catch (err) {
    console.error('Błąd aktualizacji statusu:', err.message);
    res.status(500).json({ error: 'Błąd aktualizacji' });
  }
});

// API: Statystyki
app.get('/api/stats', authenticate, (req, res) => {
  try {
    const clients = JSON.parse(fs.readFileSync(dbFile));
    const stats = {
      newCount: clients.filter(c => c.status === 'nowe').length,
      completedCount: clients.filter(c => c.status === 'zrealizowane').length,
      totalSales: clients.reduce((sum, c) => sum + (c.amount || 0), 0) / 100, // W PLN
      avgQuestions: clients.length ? (clients.reduce((sum, c) => sum + parseInt(c.questionCount), 0) / clients.length).toFixed(2) : 0
    };
    res.json(stats);
  } catch (err) {
    console.error('Błąd statystyk:', err.message);
    res.status(500).json({ error: 'Błąd statystyk' });
  }
});

// Webhook Stripe
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Błąd webhooka:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.payment_status === 'paid') {
      const { name, birthdate, email, questions, questionCount } = session.metadata;
      const clientData = {
        id: session.id,
        name,
        birthdate,
        email,
        questions: JSON.parse(questions),
        questionCount: parseInt(questionCount),
        timestamp: new Date().toISOString(),
        status: 'nowe',
        amount: prices[parseInt(questionCount)] || 0
      };

      console.log('Zapisuję dane klienta:', clientData);
      const clients = JSON.parse(fs.readFileSync(dbFile));
      clients.push(clientData);
      fs.writeFileSync(dbFile, JSON.stringify(clients, null, 2));
      console.log('Zapisano do pliku');
    }
  } else {
    console.log(`Ignoruję zdarzenie: ${event.type}, ID: ${event.id}`);
  }

  res.json({ received: true });
});

// Reszta endpointów
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d' // Cache statycznych plików na 1 dzień
}));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/create-checkout-session', async (req, res) => {
  const { name, birthdate, questions, email, questionCount } = req.body;

  if (!name || !birthdate || !email || !questions || questions.length !== parseInt(questionCount)) {
    console.log('Błąd walidacji danych:', req.body);
    return res.status(400).json({ error: 'Brakujące dane' });
  }

  const priceId = priceIds[questionCount];
  if (!priceId) {
    console.log('Nieprawidłowa liczba pytań:', questionCount);
    return res.status(400).json({ error: 'Nieprawidłowa liczba pytań' });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'payment',
      success_url: `https://2d22ca677d30.ngrok-free.app/success.html?session_id={CHECKOUT_SESSION_ID}`, ///TUTAJ EDYTUJ URL NGROKA PO JEGO PONOWNYM ODPALENIU
      cancel_url: `https://2d22ca677d30.ngrok-free.app/error.html`, ///TUTAJ EDYTUJ URL NGROKA PO JEGO PONOWNYM ODPALENIU
      metadata: { name, birthdate, email, questions: JSON.stringify(questions), questionCount },
    });

    console.log('Sesja Stripe utworzona, ID:', session.id);
    res.json({ id: session.id });
  } catch (error) {
    console.error('Błąd tworzenia sesji Stripe:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start serwera
app.listen(port, () => {
  console.log(`Serwer działa na porcie ${port}`);
});