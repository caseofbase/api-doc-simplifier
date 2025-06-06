const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

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
    
    if (domain !== 'thinairlabs.com') {
      return done(null, false, { message: 'Access restricted to thinairlabs.com email addresses' });
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

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  
  // If it's an API request, return JSON error
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Otherwise redirect to login
  res.redirect('/auth/google');
};

// Middleware to check if user has thinairlabs email
const requireThinAirLabs = (req, res, next) => {
  if (req.isAuthenticated() && req.user.email.endsWith('@thinairlabs.com')) {
    return next();
  }
  
  if (req.path.startsWith('/api/')) {
    return res.status(403).json({ error: 'Access restricted to thinairlabs.com email addresses' });
  }
  
  res.status(403).send(`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>Access Restricted</h1>
        <p>This application is only available to users with @thinairlabs.com email addresses.</p>
        <p>Please contact your administrator if you believe this is an error.</p>
        <a href="/auth/logout">Try different account</a>
      </body>
    </html>
  `);
};

module.exports = {
  passport,
  requireAuth,
  requireThinAirLabs
}; 