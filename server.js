





const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

let fetchFn;
try {
  fetchFn = fetch;
} catch (e) {
  fetchFn = require('node-fetch');
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    // Add production frontend URL here if known, e.g., 'https://your-frontend-domain.com'
    // For now, allowing localhost for development
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

// Inline Firebase Service Account Credentials
const serviceAccount = {
  "type": "service_account",
  "project_id": "loadbase-5fc06",
  "private_key_id": "61b80b788cae34043cb324ff4f300be8ad4da50e",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxYjajbmpSuTbQ\nWLlTMEmMLDtPQvUd9Hs483y6PDXpaNowVAnUTNwWGIbOm+55NtHUPu5oVysRSX3p\nOV0tj3RD9I5DoohohRxhUwL+MZUP2DxdpIMsIfHFmMtkedMEKGcEYRhQ1PwtOc5B\n/Dy+4dCfgVkCosNWnfU3ZFtW7Sd42TmqZuuAVDsluOgHGr5mxoU8eeOch8FOkLoT\nrlbYyR/AocOTdVlFejz5IQVFhCkoey8MgzLn4W2bjq7fOgPjfJqGsqszMieaPFhv\ncmxnTbQohhssjhFmz2MT7PqtzMAYSj4O8WVTurPKI/3GR2O9eyQjXkZslC1Hpr3W\nfiFBgBVtAgMBAAECggEAAiYQRxlYh4wW5e92p5kt6iqg/0q/76NdR0wxN9GTWcnH\nCzIv9Hm2ag3sdTU+P9x1FzqXA4mMl5hsts1LIYSP7cDNfC5X+XsN2HQkSUacwMT5\nAvNghnu9ga7t0Z2IWOFo9DsgUWn7Dx4YuwPNC0zjDKZ9gZQq4axm+hEF0yIOBDZ9\np35CiVU/iVyH0fBOXgAj/fxiDZVP1NCNU34JnuSUgcUZYd7Yftu/0aRIVO4T4OG/\nGN59Oqv7qqABBWI69VUA7deNif2rMUHykmG4eUtticlwXFPehQB9ubUuyvFbNToX\nccNZeL1LzoOk783l015cBubAgGblQH7A6WYnaQiKYQKBgQDzxp1zqDHqJbijJ/rT\nZezk1hxUDDY+WAOmCHVL5dv3SBMQUpscsjcPQY7x5ejtT0GpObS8mu+D2MSDs6qs\nHPAd3Nhq3V7LPhYtNHyxb4kyC7rVbKDvvWWahJcikYO9EspXVv+E2V39l0Bzavpb\nvTy6yWWV2xEjRNIRQc9kU0GHcQKBgQC6R0/5WJeImyIVuiGmzctO4/rXjzu6asRh\njhpi0On69mt44XkvnEk4FgXLKKdjaJjhC9PAUKECf3R9eyi+n+D+UXxn6X7Xydj6\nEG5Wiq+ds+FX+LIJRMTLUyK7Ym8LXUMtUFYIJJI2ePRl7whRMJleOt2LmHatRsww\nHY0o3psHvQKBgQCz1L7uRROdYXpVkfas4DHjljeLoP6a+x6l6vNsrAKa5uZ5Uhbv\nEmEftgMXW7164s7TYah8wecS4mQFrBKpqSdRQEu+edOmJwUBEAk0c81Hx/Np4hrP\nAG7lkA5WB/ahEi2GRL12aUu2+U8oVbCe4Hjeahewdsyrsectp9iwb+KVYQKBgQCC\nxrH0wieQdikVy9j4PB5xwkhGsX4jP/Wi75rCqRy7XejRsqnbrQMSZxOmL2Jkvfgm\ndqEwsOp40HY96gsO2TuiEB8g7KJqaID1/jcYdsEYHEMl+ak0LJ1kiXcmytJezhjt\nZSshCFvF9mDOd2QFa/MgXn9PE7itqbiMRxLlEHMSmQKBgGTXgQz8hbd6q4b6ARkL\noSzRCTP0vatIyImYFMhEAUcv95e3r/o8jp6lstGnijCqbdFuEV5b9TOpetGCykQY\nFg5EwhkTeI9cYQkYz3TUL+LovPFpqq9L+JUGep+ihvoBrJQAmVgMKoIqenex4Dzp\nPlxWE3sHDryLSR0NEosXsPGC\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@loadbase-5fc06.iam.gserviceaccount.com",
  "client_id": "103141873539610334582",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40loadbase-5fc06.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://loadbase-5fc06-default-rtdb.firebaseio.com/"
});

const db = admin.database();
const auth = admin.auth();

// JWT Configuration (for internal token management)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Google Maps API Key
const GOOGLE_API_KEY = 'AIzaSyCnMo9hEXw5QQTNAkXCxEan0QUT1oXNL00'; // Replace with your Google Maps API key

// Get frontend URL from environment variable or detect automatically
const getFrontendUrl = () => {
  // Use environment variable if set
  if (process.env.FRONTEND_URL) {
    return process.env.FRONTEND_URL;
  }

  // In production, use the same domain as the backend
  if (process.env.NODE_ENV === 'production') {
    // This will be set by the hosting platform (Render, Heroku, etc.)
    return process.env.RENDER_EXTERNAL_URL || process.env.HEROKU_URL || `https://${process.env.VERCEL_URL}`;
  }

  // Default to localhost for development
  return 'http://localhost:3001';
};

// Geocode address
async function geocodeAddress(address) {
  if (!address) return { lat: 0, lng: 0 };
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(
      address
    )}&key=${GOOGLE_API_KEY}`;
    const res = await fetchFn(url);
    const data = await res.json();
    if (data.status !== 'OK' || !data.results[0]) return { lat: 0, lng: 0 };
    return data.results[0].geometry.location;
  } catch (e) {
    return { lat: 0, lng: 0 };
  }
}

// Reverse geocode
async function reverseGeocode(lat, lng) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${GOOGLE_API_KEY}`;
    const res = await fetchFn(url);
    const data = await res.json();
    if (data.status !== 'OK' || !data.results[0]) return `${lat}, ${lng}`;
    return data.results[0].formatted_address;
  } catch (e) {
    return `${lat}, ${lng}`;
  }
}

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Verify JWT token
    const decodedToken = jwt.verify(token, JWT_SECRET);
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      email_verified: decodedToken.email_verified
    };
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// User Registration (creates Firebase Auth user)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role = 'user' } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Create user in Firebase Auth
    const userRecord = await auth.createUser({
      email: email,
      password: password,
      emailVerified: false
    });

    // Store additional user data in Realtime Database
    await db.ref(`users/${userRecord.uid}`).set({
      email: email,
      role: role,
      createdAt: Date.now(),
      displayName: email.split('@')[0] // Simple display name
    });

    // Send email verification (optional)
    await auth.generateEmailVerificationLink(email);

    res.json({
      message: 'User created successfully',
      uid: userRecord.uid,
      email: userRecord.email,
      role: role
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({ error: 'User already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login (Firebase handles authentication on frontend, backend verifies idToken)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ error: 'ID token required' });
    }

    // Verify the token
    const decodedToken = await auth.verifyIdToken(idToken);
    const uid = decodedToken.uid;
    const email_verified = decodedToken.email_verified;

    // Get user data from database
    const userRef = db.ref(`users/${uid}`);
    const userSnapshot = await userRef.once('value');

    let userData;
    if (!userSnapshot.exists()) {
      // Create user in database if not exists
      const userRecord = await auth.getUser(uid);
      userData = {
        email: userRecord.email,
        role: 'user',
        createdAt: Date.now(),
        displayName: userRecord.displayName || userRecord.email.split('@')[0]
      };
      await userRef.set(userData);
    } else {
      userData = userSnapshot.val();
    }

    // Generate custom JWT for additional backend security (optional)
    const customToken = jwt.sign(
      {
        uid: uid,
        email: decodedToken.email,
        email_verified: email_verified
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      uid: uid,
      email: decodedToken.email,
      email_verified: email_verified,
      customToken: customToken,
      user: { ...userData, role: userData.role || 'user' }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Get current user loads (protected route)
app.get('/api/loads', authenticateToken, async (req, res) => {
  try {
    const userLoadsRef = db.ref(`loads/${req.user.uid}`);
    const snapshot = await userLoadsRef.once('value');
    
    if (!snapshot.exists()) {
      return res.json([]);
    }

    const loads = [];
    snapshot.forEach(childSnapshot => {
      loads.push({
        id: childSnapshot.key,
        ...childSnapshot.val()
      });
    });

    // Sort by createdAt descending
    loads.sort((a, b) => b.createdAt - a.createdAt);
    res.json(loads);
  } catch (error) {
    console.error('Error fetching loads:', error);
    res.status(500).json({ error: 'Failed to fetch loads' });
  }
});

// Create load (protected route)
app.post('/api/loads', authenticateToken, async (req, res) => {
  console.log('Creating a new load');

  try {
    const { stops = [], driverPhone, geofence } = req.body;
    
    if (!stops.length) return res.status(400).json({ error: 'At least one stop is required' });
    if (!driverPhone) return res.status(400).json({ error: 'Driver phone is required' });
    if (!geofence || geofence < 0) return res.status(400).json({ error: 'Valid geofence is required' });

    const stopsWithLatLng = [];
    for (let s of stops) {
      if (!s.address) return res.status(400).json({ error: 'All stops must have an address' });
      const loc = await geocodeAddress(s.address);
      if (loc.lat === 0 && loc.lng === 0) return res.status(400).json({ error: `Invalid address: ${s.address}` });
      stopsWithLatLng.push({ type: s.type, address: s.address, lat: loc.lat, lng: loc.lng });
    }

    const frontendUrl = getFrontendUrl();
    const loadId = db.ref().child('loads').push().key; // Generate unique ID
    
    const loadData = {
      id: loadId,
      userId: req.user.uid,
      stops: stopsWithLatLng,
      driverPhone,
      geofence,
      status: 'Created',
      events: [{ type: 'Created', ts: Date.now() }],
      locations: [],
      driverLocation: null,
      trackingUrl: `${frontendUrl}/tracking/${loadId}`,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    // Store in user's loads collection
    await db.ref(`loads/${req.user.uid}/${loadId}`).set(loadData);

    // Emit to all connected clients
    io.emit('loadsUpdated', { 
      userId: req.user.uid, 
      action: 'created', 
      load: loadData 
    });
    
    console.log('Load created:', loadData);
    res.json(loadData);

  } catch (err) {
    console.error('Error creating load:', err);
    res.status(500).json({ error: 'Failed to create load' });
  }
});

// Get load by ID (public for tracking)
app.get('/api/loads/:id', async (req, res) => {
  try {
    const id = req.params.id;

    // Find the load across all users
    let loadFound = false;
    let loadData;
    const usersRef = db.ref('loads');
    const usersSnapshot = await usersRef.once('value');

    usersSnapshot.forEach(userSnapshot => {
      const userLoadsRef = userSnapshot.child(id);
      if (userLoadsRef.exists()) {
        loadData = userLoadsRef.val();
        loadData.id = id;
        loadFound = true;
      }
    });

    if (!loadFound) {
      return res.status(404).json({ error: 'Load not found' });
    }

    res.json(loadData);
  } catch (error) {
    console.error('Error fetching load:', error);
    res.status(500).json({ error: 'Failed to fetch load' });
  }
});

// Confirm load (public for driver)
app.post('/api/loads/:id/confirm', async (req, res) => {
  console.log('Confirming load:', req.params.id);

  try {
    const id = req.params.id;

    // Find the load across all users
    let loadFound = false;
    let loadRef;
    let userId;
    const usersRef = db.ref('loads');
    const usersSnapshot = await usersRef.once('value');

    usersSnapshot.forEach(userSnapshot => {
      const userLoadsRef = userSnapshot.child(id);
      if (userLoadsRef.exists()) {
        loadRef = db.ref(`loads/${userSnapshot.key}/${id}`);
        userId = userSnapshot.key;
        loadFound = true;
      }
    });

    if (!loadFound) {
      return res.status(404).json({ error: 'Load not found' });
    }

    const snapshot = await loadRef.once('value');
    const load = snapshot.val();

    if (load.status !== 'Created') {
      return res.status(400).json({ error: 'Load already confirmed or canceled' });
    }

    // Update load
    await loadRef.update({
      status: 'Confirmed',
      events: [...load.events, { type: 'Confirmed', ts: Date.now() }],
      updatedAt: Date.now()
    });

    const updatedLoad = { ...load, status: 'Confirmed', updatedAt: Date.now() };
    updatedLoad.events = [...updatedLoad.events, { type: 'Confirmed', ts: Date.now() }];

    io.emit('loadsUpdated', {
      userId: userId,
      action: 'updated',
      load: updatedLoad
    });

    console.log('Load confirmed:', updatedLoad);
    res.json({ trackingUrl: updatedLoad.trackingUrl });

  } catch (error) {
    console.error('Error confirming load:', error);
    res.status(500).json({ error: 'Failed to confirm load' });
  }
});

// Cancel load (public for driver)
app.post('/api/loads/:id/cancel', async (req, res) => {
  console.log('Cancelling load:', req.params.id);

  try {
    const id = req.params.id;

    // Find the load across all users
    let loadFound = false;
    let loadRef;
    let userId;
    const usersRef = db.ref('loads');
    const usersSnapshot = await usersRef.once('value');

    usersSnapshot.forEach(userSnapshot => {
      const userLoadsRef = userSnapshot.child(id);
      if (userLoadsRef.exists()) {
        loadRef = db.ref(`loads/${userSnapshot.key}/${id}`);
        userId = userSnapshot.key;
        loadFound = true;
      }
    });

    if (!loadFound) {
      return res.status(404).json({ error: 'Load not found' });
    }

    const snapshot = await loadRef.once('value');
    const load = snapshot.val();

    if (load.status !== 'Created') {
      return res.status(400).json({ error: 'Load already confirmed or canceled' });
    }

    // Update load
    await loadRef.update({
      status: 'Canceled',
      events: [...load.events, { type: 'Canceled', ts: Date.now() }],
      updatedAt: Date.now()
    });

    const updatedLoad = { ...load, status: 'Canceled', updatedAt: Date.now() };
    updatedLoad.events = [...updatedLoad.events, { type: 'Canceled', ts: Date.now() }];

    io.emit('loadsUpdated', {
      userId: userId,
      action: 'updated',
      load: updatedLoad
    });

    console.log('Load canceled:', updatedLoad);
    res.json({ message: 'Load canceled' });

  } catch (error) {
    console.error('Error canceling load:', error);
    res.status(500).json({ error: 'Failed to cancel load' });
  }
});

// Complete load
app.post('/api/loads/:id/complete', authenticateToken, async (req, res) => {
  console.log('Completing load:', req.params.id);

  try {
    const loadRef = db.ref(`loads/${req.user.uid}/${req.params.id}`);
    const snapshot = await loadRef.once('value');

    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Load not found' });
    }

    const load = snapshot.val();
    if (load.status !== 'Confirmed') {
      return res.status(400).json({ error: 'Load not confirmed or already completed' });
    }

    // Update load
    await loadRef.update({
      status: 'Completed',
      events: [...load.events, { type: 'Completed', ts: Date.now() }],
      updatedAt: Date.now()
    });

    const updatedLoad = { ...load, status: 'Completed', updatedAt: Date.now() };
    updatedLoad.events = [...updatedLoad.events, { type: 'Completed', ts: Date.now() }];

    io.emit('loadsUpdated', {
      userId: req.user.uid,
      action: 'updated',
      load: updatedLoad
    });

    console.log('Load completed:', updatedLoad);
    res.json({ message: 'Load completed' });

  } catch (error) {
    console.error('Error completing load:', error);
    res.status(500).json({ error: 'Failed to complete load' });
  }
});

// Update driver location (public endpoint for drivers - verify load exists)
app.post('/api/loads/:id/location', async (req, res) => {
  try {
    const id = req.params.id;
    const { lat, lng } = req.body;
    
    if (!lat || !lng) {
      return res.status(400).json({ error: 'Valid coordinates required' });
    }

    // Find the load across all users (for driver updates)
    let loadFound = false;
    let loadRef;
    const usersRef = db.ref('loads');
    const usersSnapshot = await usersRef.once('value');
    
    usersSnapshot.forEach(userSnapshot => {
      const userLoadsRef = userSnapshot.child(id);
      if (userLoadsRef.exists()) {
        loadRef = db.ref(`loads/${userSnapshot.key}/${id}`);
        loadFound = true;
      }
    });

    if (!loadFound) {
      return res.status(404).json({ error: 'Load not found' });
    }

    const snapshot = await loadRef.once('value');
    const load = snapshot.val();
    
    if (load.status !== 'Confirmed') {
      return res.status(400).json({ error: 'Load not confirmed' });
    }

    const city = await reverseGeocode(lat, lng);
    const loc = { lat, lng, city, timestamp: Date.now() };
    
    // Update load
    await loadRef.update({
      driverLocation: loc,
      locations: [...(load.locations || []), loc],
      events: [...load.events, { type: 'LocationUpdate', ts: Date.now(), meta: loc }],
      updatedAt: Date.now()
    });

    const updatedLoad = { ...load, driverLocation: loc, updatedAt: Date.now() };
    updatedLoad.locations = [...(updatedLoad.locations || []), loc];
    updatedLoad.events = [...updatedLoad.events, { type: 'LocationUpdate', ts: Date.now(), meta: loc }];

    // Emit to socket room
    io.to(id).emit('location_update', loc);
    io.emit('loadsUpdated', { 
      userId: load.userId, 
      action: 'updated', 
      load: updatedLoad 
    });
    
    res.json({ message: 'Driver location updated' });
  } catch (error) {
    console.error('Error updating location:', error);
    res.status(500).json({ error: 'Failed to update location' });
  }
});

// Delete load (optional)
app.delete('/api/loads/:id', authenticateToken, async (req, res) => {
  try {
    const loadRef = db.ref(`loads/${req.user.uid}/${req.params.id}`);
    await loadRef.remove();
    
    io.emit('loadsUpdated', { 
      userId: req.user.uid, 
      action: 'deleted', 
      loadId: req.params.id 
    });
    
    res.json({ message: 'Load deleted successfully' });
  } catch (error) {
    console.error('Error deleting load:', error);
    res.status(500).json({ error: 'Failed to delete load' });
  }
});

// Socket.IO with JWT Auth
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  try {
    const decodedToken = jwt.verify(token, JWT_SECRET);
    socket.user = {
      uid: decodedToken.uid,
      email: decodedToken.email
    };
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id, 'User:', socket.user?.email);

  socket.on('join_load', async (loadId) => {
    // Verify user has access to this load
    const userLoadsRef = db.ref(`loads/${socket.user.uid}`);
    const loadSnapshot = await userLoadsRef.child(loadId).once('value');
    
    if (loadSnapshot.exists()) {
      socket.join(loadId);
      const load = loadSnapshot.val();
      load.id = loadId;
      socket.emit('load_details', load);
      
      if (load.driverLocation) {
        socket.emit('location_update', load.driverLocation);
      }
    } else {
      socket.emit('error', 'Access denied to this load');
    }
  });

  // Handle driver location updates via socket
  socket.on('driver_location_update', async (data) => {
    const { loadId, location } = data;
    
    if (!location.lat || !location.lng) {
      socket.emit('error', 'Valid coordinates required');
      return;
    }

    // Find the load across all users (for driver updates)
    let loadFound = false;
    let loadRef;
    let userId;
    const usersRef = db.ref('loads');
    const usersSnapshot = await usersRef.once('value');
    
    usersSnapshot.forEach(userSnapshot => {
      const userLoadsRef = userSnapshot.child(loadId);
      if (userLoadsRef.exists()) {
        loadRef = db.ref(`loads/${userSnapshot.key}/${loadId}`);
        userId = userSnapshot.key;
        loadFound = true;
      }
    });

    if (!loadFound) {
      socket.emit('error', 'Load not found');
      return;
    }

    const snapshot = await loadRef.once('value');
    const load = snapshot.val();
    
    if (load.status !== 'Confirmed') {
      socket.emit('error', 'Load not confirmed');
      return;
    }

    try {
      const city = await reverseGeocode(location.lat, location.lng);
      const loc = { lat: location.lat, lng: location.lng, city, timestamp: Date.now() };

      // Update load
      await loadRef.update({
        driverLocation: loc,
        locations: [...(load.locations || []), loc],
        events: [...load.events, { type: 'LocationUpdate', ts: Date.now(), meta: loc }],
        updatedAt: Date.now()
      });

      const updatedLoad = { ...load, driverLocation: loc, updatedAt: Date.now() };
      updatedLoad.locations = [...(updatedLoad.locations || []), loc];
      updatedLoad.events = [...updatedLoad.events, { type: 'LocationUpdate', ts: Date.now(), meta: loc }];

      // Broadcast to room
      io.to(loadId).emit('location_update', loc);
      io.emit('loadsUpdated', { 
        userId: userId, 
        action: 'updated', 
        load: updatedLoad 
      });

      console.log(`📍 Driver location updated for load ${loadId}:`, loc);
      socket.emit('success', 'Location updated');
    } catch (error) {
      console.error('Error updating driver location:', error);
      socket.emit('error', 'Failed to update location');
    }
  });

  socket.on('disconnect', () => console.log('Socket disconnected:', socket.id));
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
