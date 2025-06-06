const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

// Configure Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Check if email domain is allowed
    const email = profile.emails[0].value;
    const domain = email.split('@')[1];
    
    if (domain !== 'thinairlabs.ca') {
      return done(null, false, { message: 'Access restricted to thinairlabs.ca email addresses' });
    }
    
    // Create user object
    const user = {
      id: profile.id,
      email: email,
      name: profile.displayName,
      picture: profile.photos[0]?.value
    };
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Serialize user for session (still needed for OAuth flow)
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from session (still needed for OAuth flow)
passport.deserializeUser((user, done) => {
  done(null, user);
});

// JWT helper functions
const generateJWT = (user) => {
  return jwt.sign(
    { 
      id: user.id, 
      email: user.email, 
      name: user.name, 
      picture: user.picture 
    },
    process.env.SESSION_SECRET || 'your-secret-key-change-this',
    { expiresIn: '24h' }
  );
};

const verifyJWT = (token) => {
  try {
    return jwt.verify(token, process.env.SESSION_SECRET || 'your-secret-key-change-this');
  } catch (error) {
    return null;
  }
};

// Middleware to check JWT authentication
const requireJWTAuth = (req, res, next) => {
  const token = req.cookies.auth_token;
  
  if (!token) {
    // If it's an API request, return JSON error
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    // Otherwise redirect to login
    return res.redirect('/auth/google');
  }
  
  const user = verifyJWT(token);
  if (!user) {
    // Token invalid or expired
    res.clearCookie('auth_token');
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/auth/google');
  }
  
  // Attach user to request
  req.user = user;
  req.isAuthenticated = () => true;
  next();
};

// Middleware to check if user has thinairlabs email (for JWT)
const requireThinAirLabsJWT = (req, res, next) => {
  const token = req.cookies.auth_token;
  
  if (!token) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/auth/google');
  }
  
  const user = verifyJWT(token);
  if (!user || !user.email.endsWith('@thinairlabs.ca')) {
    res.clearCookie('auth_token');
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Access restricted to thinairlabs.ca email addresses' });
    }
    
    res.status(403).send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>Access Restricted</h1>
          <p>This application is only available to users with @thinairlabs.ca email addresses.</p>
          <p>Please contact your administrator if you believe this is an error.</p>
          <a href="/auth/logout">Try different account</a>
        </body>
      </html>
    `);
    return;
  }
  
  // Attach user to request
  req.user = user;
  req.isAuthenticated = () => true;
  next();
};

module.exports = {
  passport,
  generateJWT,
  verifyJWT,
  requireJWTAuth,
  requireThinAirLabsJWT
}; 