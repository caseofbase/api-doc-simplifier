require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const SwaggerParser = require('swagger-parser');
const YAML = require('yamljs');
const OpenAI = require('openai');
const axios = require('axios');
const cheerio = require('cheerio');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { passport, generateJWT, requireThinAirLabsJWT } = require('./auth-jwt');

const app = express();
const PORT = process.env.PORT || 3002;

// Initialize OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: true, // Force session save for serverless
  saveUninitialized: true, // Save uninitialized sessions for serverless
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Important for OAuth redirects
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.json', '.yaml', '.yml'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON, YAML, and YML files are allowed'));
    }
  }
});

// Helper function to find API specification URLs from documentation websites
async function findApiSpecFromDocs(docUrl) {
  try {
    console.log(`Searching for API specs at: ${docUrl}`);
    
    // First, try common API spec endpoints
    const baseUrl = new URL(docUrl).origin;
    const commonPaths = [
      '/swagger.json',
      '/openapi.json',
      '/api-docs',
      '/api/swagger.json',
      '/api/openapi.json',
      '/docs/swagger.json',
      '/docs/openapi.json',
      '/v1/swagger.json',
      '/v2/swagger.json',
      '/swagger/v1/swagger.json',
      '/api/v1/swagger.json',
      '/api/docs/swagger.json',
      '/api/docs/openapi.json',
      '/reference/swagger.json',
      '/reference/openapi.json'
    ];

    // Try common endpoints first
    for (const path of commonPaths) {
      try {
        const testUrl = baseUrl + path;
        console.log(`Trying: ${testUrl}`);
        const response = await axios.get(testUrl, { timeout: 5000 });
        if (response.data && (response.data.swagger || response.data.openapi)) {
          console.log(`Found API spec at: ${testUrl}`);
          return testUrl;
        }
      } catch (error) {
        // Continue to next path
      }
    }

    // If common paths don't work, scrape the documentation page
    console.log('Scraping documentation page for API spec links...');
    const response = await axios.get(docUrl, { timeout: 10000 });
    const $ = cheerio.load(response.data);
    
    // Look for links to API specifications
    const specLinks = [];
    
    // Check for direct links to JSON/YAML files
    $('a[href*=".json"], a[href*=".yaml"], a[href*=".yml"]').each((i, elem) => {
      const href = $(elem).attr('href');
      if (href && (href.includes('swagger') || href.includes('openapi') || href.includes('api'))) {
        const fullUrl = href.startsWith('http') ? href : new URL(href, docUrl).href;
        specLinks.push(fullUrl);
      }
    });

    // Check for links containing swagger/openapi keywords
    $('a[href*="swagger"], a[href*="openapi"], a[href*="api-docs"]').each((i, elem) => {
      const href = $(elem).attr('href');
      if (href) {
        const fullUrl = href.startsWith('http') ? href : new URL(href, docUrl).href;
        specLinks.push(fullUrl);
      }
    });

    // Look for embedded JSON-LD or script tags with API specs
    $('script[type="application/json"], script[type="application/ld+json"]').each((i, elem) => {
      const content = $(elem).html();
      try {
        const json = JSON.parse(content);
        if (json.swagger || json.openapi) {
          // Found embedded spec
          return json;
        }
      } catch (e) {
        // Not valid JSON, continue
      }
    });

    // Try the most promising links
    for (const link of specLinks) {
      try {
        console.log(`Testing scraped link: ${link}`);
        const testResponse = await axios.get(link, { timeout: 5000 });
        if (testResponse.data && (testResponse.data.swagger || testResponse.data.openapi)) {
          console.log(`Found API spec at scraped link: ${link}`);
          return link;
        }
      } catch (error) {
        // Continue to next link
      }
    }

    // If no OpenAPI spec found, try to create one from the documentation structure
    console.log('No OpenAPI spec found, attempting to parse documentation structure...');
    return await createSpecFromDocumentation(docUrl, $, response.data);
    
  } catch (error) {
    throw new Error(`Failed to find API specification: ${error.message}`);
  }
}

// Helper function to create a basic API spec from documentation structure
async function createSpecFromDocumentation(docUrl, $, html) {
  try {
    const baseUrl = new URL(docUrl).origin;
    const title = $('title').text() || $('h1').first().text() || 'API Documentation';
    
    // Create a basic OpenAPI structure
    const apiSpec = {
      openapi: '3.0.0',
      info: {
        title: title.replace(' Documentation', '').replace(' API', '') + ' API',
        version: '1.0.0',
        description: $('meta[name="description"]').attr('content') || 
                    $('p').first().text() || 
                    'API documentation parsed from website'
      },
      servers: [
        {
          url: baseUrl,
          description: 'API Server'
        }
      ],
      paths: {}
    };

    // Look for API endpoints in the documentation
    const endpoints = [];
    
    // Common patterns for API endpoints in documentation
    const endpointPatterns = [
      /\/api\/[^\s<>"']+/g,
      /\/v\d+\/[^\s<>"']+/g,
      /POST|GET|PUT|DELETE|PATCH\s+[^\s<>"']+/g
    ];

    // Search for endpoints in text content
    const textContent = $.text();
    endpointPatterns.forEach(pattern => {
      const matches = textContent.match(pattern);
      if (matches) {
        matches.forEach(match => {
          // Clean up the match
          const cleaned = match.replace(/[<>"']/g, '').trim();
          if (cleaned.startsWith('/') && cleaned.length > 1) {
            endpoints.push(cleaned);
          }
        });
      }
    });

    // Look for structured API documentation sections
    $('h1, h2, h3, h4').each((i, elem) => {
      const heading = $(elem).text().toLowerCase();
      if (heading.includes('endpoint') || heading.includes('api') || 
          heading.includes('post') || heading.includes('get') ||
          heading.includes('put') || heading.includes('delete')) {
        
        // Look for code blocks or paths near this heading
        const nextElements = $(elem).nextAll().slice(0, 5);
        nextElements.each((j, nextElem) => {
          const text = $(nextElem).text();
          const pathMatch = text.match(/\/[a-zA-Z0-9\/_-]+/);
          if (pathMatch) {
            endpoints.push(pathMatch[0]);
          }
        });
      }
    });

    // Enhanced parsing for Apollo-style documentation
    const useCases = [];
    $('li, p').each((i, elem) => {
      const text = $(elem).text();
      
      // Look for API use cases and features
      if (text.includes('endpoint') || text.includes('API') || text.includes('data')) {
        const lowerText = text.toLowerCase();
        if (lowerText.includes('enrich') || lowerText.includes('search') || 
            lowerText.includes('find') || lowerText.includes('retrieve') ||
            lowerText.includes('create') || lowerText.includes('integration')) {
          useCases.push(text.trim());
        }
      }
    });

    // Create endpoints based on discovered use cases
    if (useCases.length > 0) {
      const commonApiPaths = [
        '/api/people/search',
        '/api/people/enrich',
        '/api/organizations/enrich',
        '/api/accounts',
        '/api/contacts',
        '/api/sequences'
      ];
      
      commonApiPaths.forEach(path => {
        endpoints.push(path);
      });
    }

    // Remove duplicates and add to spec
    const uniqueEndpoints = [...new Set(endpoints)].slice(0, 20); // Limit to 20 endpoints
    
    uniqueEndpoints.forEach(endpoint => {
      if (!apiSpec.paths[endpoint]) {
        let summary = `${endpoint} endpoint`;
        let description = `API endpoint found in documentation`;
        let methods = ['get'];
        
        // Enhanced endpoint descriptions based on path
        if (endpoint.includes('search')) {
          summary = 'Search for records';
          description = 'Search and filter records based on criteria';
          methods = ['post'];
        } else if (endpoint.includes('enrich')) {
          summary = 'Enrich data';
          description = 'Enhance existing data with additional information';
          methods = ['post'];
        } else if (endpoint.includes('people')) {
          summary = 'People operations';
          description = 'Operations related to people and contacts';
        } else if (endpoint.includes('organizations')) {
          summary = 'Organization operations';
          description = 'Operations related to organizations and companies';
        } else if (endpoint.includes('accounts')) {
          summary = 'Account management';
          description = 'Create, update, and manage accounts';
          methods = ['get', 'post', 'put'];
        } else if (endpoint.includes('contacts')) {
          summary = 'Contact management';
          description = 'Create, update, and manage contacts';
          methods = ['get', 'post', 'put'];
        } else if (endpoint.includes('sequences')) {
          summary = 'Sequence operations';
          description = 'Manage email sequences and campaigns';
          methods = ['get', 'post'];
        }
        
        apiSpec.paths[endpoint] = {};
        methods.forEach(method => {
          apiSpec.paths[endpoint][method] = {
            summary: summary,
            description: description,
            responses: {
              '200': {
                description: 'Successful response'
              },
              '400': {
                description: 'Bad request'
              },
              '401': {
                description: 'Unauthorized'
              }
            }
          };
        });
      }
    });

    // If no endpoints found, create a generic one
    if (Object.keys(apiSpec.paths).length === 0) {
      apiSpec.paths['/api'] = {
        get: {
          summary: 'API endpoint',
          description: 'Generic API endpoint',
          responses: {
            '200': {
              description: 'Successful response'
            }
          }
        }
      };
    }

    console.log(`Created API spec with ${Object.keys(apiSpec.paths).length} endpoints from documentation`);
    return apiSpec;
    
  } catch (error) {
    throw new Error('No API specification found at the provided documentation URL');
  }
}

// Helper function to parse API documentation
async function parseApiDoc(filePath) {
  try {
    const ext = path.extname(filePath).toLowerCase();
    let apiDoc;

    if (ext === '.json') {
      const content = fs.readFileSync(filePath, 'utf8');
      apiDoc = JSON.parse(content);
    } else if (ext === '.yaml' || ext === '.yml') {
      apiDoc = YAML.load(filePath);
    }

    // Validate and dereference the API document
    const api = await SwaggerParser.validate(apiDoc);
    return api;
  } catch (error) {
    throw new Error(`Failed to parse API document: ${error.message}`);
  }
}

// Helper function to create a summary of API doc for OpenAI processing
function createApiSummary(apiDoc) {
  const summary = {
    info: apiDoc.info || {},
    servers: apiDoc.servers || [],
    pathCount: Object.keys(apiDoc.paths || {}).length,
    paths: {},
    components: {
      schemasCount: Object.keys(apiDoc.components?.schemas || {}).length
    }
  };

  // Include only the most important paths (limit to 10 to stay under token limit)
  const paths = Object.entries(apiDoc.paths || {}).slice(0, 10);
  for (const [path, methods] of paths) {
    summary.paths[path] = {};
    for (const [method, details] of Object.entries(methods)) {
      if (typeof details === 'object' && details !== null) {
        summary.paths[path][method] = {
          summary: details.summary || 'No summary',
          description: details.description || 'No description',
          tags: details.tags || [],
          parameters: details.parameters?.length || 0,
          responses: Object.keys(details.responses || {})
        };
      }
    }
  }

  return summary;
}

// Helper function to simplify API documentation using OpenAI
async function simplifyApiDoc(apiDoc) {
  try {
    // Create a smaller summary to stay within token limits
    const apiSummary = createApiSummary(apiDoc);
    
    const prompt = `
You are an expert at making technical API documentation accessible to non-technical users. 
Please analyze the following API documentation summary and create a simplified, user-friendly explanation.

IMPORTANT: Format your response using HTML tags for better readability:
- Use <h3> for main section headings
- Use <strong> for emphasis instead of **bold**
- Use <ul> and <li> for lists
- Use <p> for paragraphs
- Use <code> for endpoint names
- Make it visually appealing and easy to scan

Structure your response with these sections:
1. What this API does in simple terms
2. Main features and capabilities  
3. Common use cases
4. Key endpoints explained in plain English
5. Authentication requirements (if any)
6. Rate limits or important restrictions

Make it conversational and easy to understand for someone without technical background.

API Documentation Summary:
${JSON.stringify(apiSummary, null, 2)}

Please provide a clear, well-formatted HTML response that a business user could easily understand.
`;

    const response = await openai.chat.completions.create({
      model: "gpt-3.5-turbo", // Using 3.5-turbo for better rate limits
      messages: [
        {
          role: "system",
          content: "You are a helpful assistant that explains technical API documentation in simple, non-technical terms."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 1500,
      temperature: 0.7
    });

    return response.choices[0].message.content;
  } catch (error) {
    throw new Error(`Failed to simplify API documentation: ${error.message}`);
  }
}

// Helper function to extract key information from API doc
function extractApiInfo(apiDoc) {
  const info = {
    title: apiDoc.info?.title || 'API Documentation',
    version: apiDoc.info?.version || 'Unknown',
    description: apiDoc.info?.description || 'No description available',
    baseUrl: apiDoc.servers?.[0]?.url || 'Not specified',
    endpoints: [],
    totalEndpoints: 0,
    methods: new Set(),
    tags: new Set()
  };

  // Extract endpoint information
  if (apiDoc.paths) {
    for (const [path, methods] of Object.entries(apiDoc.paths)) {
      for (const [method, details] of Object.entries(methods)) {
        if (typeof details === 'object' && details !== null) {
          info.endpoints.push({
            path,
            method: method.toUpperCase(),
            summary: details.summary || 'No summary',
            description: details.description || 'No description',
            tags: details.tags || []
          });
          info.methods.add(method.toUpperCase());
          if (details.tags) {
            details.tags.forEach(tag => info.tags.add(tag));
          }
        }
      }
    }
  }

  info.totalEndpoints = info.endpoints.length;
  info.methods = Array.from(info.methods);
  info.tags = Array.from(info.tags);

  return info;
}

// Authentication Routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/auth/error' }),
  (req, res) => {
    // Successful authentication - generate JWT token
    const token = generateJWT(req.user);
    
    // Set JWT token as HTTP-only cookie
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    console.log('OAuth callback success - User:', req.user?.email);
    res.redirect('/');
  }
);

app.get('/auth/error', (req, res) => {
  console.log('OAuth error - User redirected to error page');
  res.send(`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>Authentication Error</h1>
        <p>Access is restricted to @thinairlabs.ca email addresses only.</p>
        <p>Please use your ThinAir Labs Google account to access this application.</p>
        <a href="/auth/google">Try Again</a>
      </body>
    </html>
  `);
});

app.get('/auth/logout', (req, res) => {
  // Clear JWT token cookie
  res.clearCookie('auth_token');
  
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

app.get('/auth/user', requireThinAirLabsJWT, (req, res) => {
  res.json({
    user: {
      name: req.user.name,
      email: req.user.email,
      picture: req.user.picture
    }
  });
});

// Temporary debug route for production troubleshooting
app.get('/auth/debug', (req, res) => {
  const token = req.cookies.auth_token;
  const { verifyJWT } = require('./auth-jwt');
  const user = token ? verifyJWT(token) : null;
  
  res.json({
    isAuthenticated: !!user,
    user: user,
    hasToken: !!token,
    environment: process.env.NODE_ENV,
    hasSessionSecret: !!process.env.SESSION_SECRET
  });
});



// Protected static file serving
app.use('/public', requireThinAirLabsJWT, express.static('public'));

// Routes
app.get('/', requireThinAirLabsJWT, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Upload and process API documentation file
app.post('/api/upload', requireThinAirLabsJWT, upload.single('apiDoc'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log('Processing uploaded file:', req.file.filename);

    // Parse the API documentation
    const apiDoc = await parseApiDoc(req.file.path);
    
    // Extract basic information
    const apiInfo = extractApiInfo(apiDoc);
    
    // Generate simplified explanation
    const simplifiedExplanation = await simplifyApiDoc(apiDoc);

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      apiInfo,
      simplifiedExplanation,
      message: 'API documentation processed successfully'
    });

  } catch (error) {
    console.error('Error processing API documentation:', error);
    
    // Clean up uploaded file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({ 
      error: 'Failed to process API documentation',
      details: error.message 
    });
  }
});

// Process API documentation from URL
app.post('/api/process-url', requireThinAirLabsJWT, async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    console.log('Processing documentation from URL:', url);

    // Check if this is a direct API spec URL or a documentation website
    const isDirect = url.includes('.json') || url.includes('.yaml') || url.includes('.yml') || 
                    url.includes('swagger.json') || url.includes('openapi.json');
    
    if (isDirect) {
      // Handle direct OpenAPI/Swagger spec files
      console.log('Processing direct API specification file...');
      try {
        const apiDoc = await SwaggerParser.validate(url);
        const apiInfo = extractApiInfo(apiDoc);
        const simplifiedExplanation = await simplifyApiDoc(apiDoc);

        return res.json({
          success: true,
          apiInfo,
          simplifiedExplanation,
          analysisType: 'openapi-spec',
          message: 'API specification processed successfully'
        });
      } catch (specError) {
        console.log('Failed to parse as OpenAPI spec, falling back to intelligent analysis');
      }
    }

    // Use intelligent documentation analysis for complex sites
    console.log('Using intelligent documentation analysis...');
    const siteInfo = await analyzeDocumentationSite(url);
    const intelligentSummary = await createIntelligentSummary(siteInfo);

    // Also try to find traditional API specs as a bonus
    let foundApiSpec = null;
    try {
      const specResult = await findApiSpecFromDocs(url);
      if (typeof specResult === 'string') {
        foundApiSpec = specResult;
      }
    } catch (error) {
      // No traditional API spec found, that's okay
      console.log('No traditional API spec found, using intelligent analysis only');
    }

    res.json({
      success: true,
      siteInfo: {
        title: siteInfo.title,
        serviceType: siteInfo.serviceType,
        knownService: siteInfo.knownService,
        url: siteInfo.url,
        keyTopics: siteInfo.keyTopics.slice(0, 10),
        apiEndpoints: siteInfo.apiEndpoints.slice(0, 5),
        rateLimits: siteInfo.rateLimits,
        authenticationMethods: siteInfo.authenticationMethods.slice(0, 3)
      },
      intelligentSummary,
      foundApiSpec,
      analysisType: 'intelligent-analysis',
      message: 'Documentation analyzed successfully using AI-powered analysis'
    });

  } catch (error) {
    console.error('Error processing documentation from URL:', error);
    
    let errorMessage = 'Failed to process documentation from URL';
    let details = error.message;
    
    if (error.message.includes('timeout')) {
      errorMessage = 'Request timeout';
      details = 'The documentation site took too long to respond. Please try again or check if the URL is accessible.';
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Cannot access URL';
      details = 'Unable to access the provided URL. Please check that the URL is correct and accessible.';
    } else if (error.message.includes('Failed to create intelligent summary')) {
      errorMessage = 'AI analysis failed';
      details = 'The AI analysis encountered an error. This might be due to API limits or complex content structure.';
    }
    
    res.status(500).json({ 
      error: errorMessage,
      details: details
    });
  }
});

// Process raw API documentation JSON/YAML
app.post('/api/process-raw', requireThinAirLabsJWT, async (req, res) => {
  try {
    const { content, format } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    console.log('Processing raw API documentation');

    let apiDoc;
    
    if (format === 'yaml') {
      apiDoc = YAML.parse(content);
    } else {
      apiDoc = JSON.parse(content);
    }

    // Validate the API documentation
    const validatedDoc = await SwaggerParser.validate(apiDoc);
    
    // Extract basic information
    const apiInfo = extractApiInfo(validatedDoc);
    
    // Generate simplified explanation
    const simplifiedExplanation = await simplifyApiDoc(validatedDoc);

    res.json({
      success: true,
      apiInfo,
      simplifiedExplanation,
      message: 'API documentation processed successfully'
    });

  } catch (error) {
    console.error('Error processing raw API documentation:', error);
    res.status(500).json({ 
      error: 'Failed to process API documentation',
      details: error.message 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'API Doc Simplifier'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    details: error.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 API Doc Simplifier server running on port ${PORT}`);
  console.log(`📖 Open http://localhost:${PORT} to get started`);
  
  if (!process.env.OPENAI_API_KEY) {
    console.warn('⚠️  Warning: OPENAI_API_KEY not found in environment variables');
    console.warn('   Please create a .env file with your OpenAI API key');
  }
});

module.exports = app; 

// Helper function to intelligently analyze documentation websites
async function analyzeDocumentationSite(url) {
  try {
    console.log(`Intelligently analyzing documentation site: ${url}`);
    
    const response = await axios.get(url, { 
      timeout: 15000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; API-Doc-Simplifier/1.0)'
      }
    });
    
    const $ = cheerio.load(response.data);
    const baseUrl = new URL(url).origin;
    
    // Extract comprehensive site information
    const siteInfo = {
      title: $('title').text() || $('h1').first().text() || 'Documentation',
      description: $('meta[name="description"]').attr('content') || 
                  $('meta[property="og:description"]').attr('content') || 
                  $('p').first().text() || '',
      url: url,
      baseUrl: baseUrl,
      favicon: $('link[rel="icon"]').attr('href') || $('link[rel="shortcut icon"]').attr('href'),
      
      // Content analysis
      mainContent: '',
      navigationStructure: [],
      keyTopics: [],
      codeExamples: [],
      
      // Technical details
      apiEndpoints: [],
      authenticationMethods: [],
      rateLimits: [],
      sdks: [],
      
      // Service identification
      serviceType: 'unknown',
      knownService: null
    };

    // Identify known services/platforms
    const serviceIdentifiers = {
      'apollo': {
        keywords: ['apollo', 'graphql', 'federation', 'supergraph', 'router'],
        type: 'GraphQL Platform',
        description: 'Apollo GraphQL is a comprehensive platform for building, managing, and scaling GraphQL APIs'
      },
      'stripe': {
        keywords: ['stripe', 'payment', 'billing', 'checkout'],
        type: 'Payment Platform',
        description: 'Stripe is a payment processing platform for online businesses'
      },
      'twilio': {
        keywords: ['twilio', 'sms', 'voice', 'messaging', 'sendgrid'],
        type: 'Communication Platform',
        description: 'Twilio provides cloud communications platform as a service'
      },
      'github': {
        keywords: ['github', 'git', 'repository', 'octocat', 'pull request'],
        type: 'Development Platform',
        description: 'GitHub is a platform for version control and collaboration'
      },
      'aws': {
        keywords: ['aws', 'amazon web services', 'ec2', 's3', 'lambda'],
        type: 'Cloud Platform',
        description: 'Amazon Web Services provides cloud computing services'
      },
      'openai': {
        keywords: ['openai', 'gpt', 'chatgpt', 'dall-e', 'whisper'],
        type: 'AI Platform',
        description: 'OpenAI provides artificial intelligence APIs and models'
      },
      'slack': {
        keywords: ['slack', 'workspace', 'channel', 'bot api'],
        type: 'Collaboration Platform',
        description: 'Slack is a business communication platform'
      },
      'shopify': {
        keywords: ['shopify', 'storefront', 'admin api', 'graphql admin'],
        type: 'E-commerce Platform',
        description: 'Shopify is an e-commerce platform for online stores'
      },
      'discord': {
        keywords: ['discord', 'bot', 'guild', 'webhook'],
        type: 'Communication Platform',
        description: 'Discord is a voice, video and text communication service'
      },
      'notion': {
        keywords: ['notion', 'database', 'page', 'block'],
        type: 'Productivity Platform',
        description: 'Notion is an all-in-one workspace for notes, tasks, wikis, and databases'
      }
    };

    // Identify the service
    const pageText = response.data.toLowerCase();
    for (const [service, config] of Object.entries(serviceIdentifiers)) {
      if (config.keywords.some(keyword => pageText.includes(keyword))) {
        siteInfo.knownService = service;
        siteInfo.serviceType = config.type;
        siteInfo.description = config.description;
        break;
      }
    }

    // Extract main content (remove navigation, headers, footers)
    const contentSelectors = [
      'main', 
      '.content', 
      '.documentation', 
      '.docs-content',
      'article',
      '.main-content',
      '#content'
    ];
    
    let mainContentElement = null;
    for (const selector of contentSelectors) {
      const element = $(selector);
      if (element.length > 0) {
        mainContentElement = element.first();
        break;
      }
    }
    
    if (!mainContentElement) {
      mainContentElement = $('body');
    }

    // Extract text content, preserving structure
    siteInfo.mainContent = mainContentElement.text().replace(/\s+/g, ' ').trim().substring(0, 8000);

    // Extract navigation structure
    $('nav a, .nav a, .navigation a, .sidebar a, .menu a').each((i, elem) => {
      const text = $(elem).text().trim();
      const href = $(elem).attr('href');
      if (text && href && text.length < 100) {
        siteInfo.navigationStructure.push({
          text: text,
          href: href.startsWith('http') ? href : new URL(href, url).href
        });
      }
    });

    // Extract headings for topic analysis
    $('h1, h2, h3, h4').each((i, elem) => {
      const text = $(elem).text().trim();
      if (text && text.length < 200) {
        siteInfo.keyTopics.push(text);
      }
    });

    // Look for code examples
    $('pre code, .highlight, .code-block, code').each((i, elem) => {
      const code = $(elem).text().trim();
      if (code && code.length > 20 && code.length < 1000) {
        siteInfo.codeExamples.push(code);
      }
    });

    // Look for API endpoints in text
    const endpointPatterns = [
      /https?:\/\/[^\s]+\/api\/[^\s]*/gi,
      /\/api\/[a-zA-Z0-9\/\-_]*/gi,
      /POST|GET|PUT|DELETE|PATCH\s+\/[a-zA-Z0-9\/\-_]*/gi
    ];

    endpointPatterns.forEach(pattern => {
      const matches = siteInfo.mainContent.match(pattern) || [];
      siteInfo.apiEndpoints.push(...matches.slice(0, 10)); // Limit to prevent spam
    });

    // Look for authentication information
    const authKeywords = ['authentication', 'auth', 'api key', 'bearer token', 'oauth', 'jwt'];
    authKeywords.forEach(keyword => {
      const regex = new RegExp(`${keyword}[^.]*\\.`, 'gi');
      const matches = siteInfo.mainContent.match(regex) || [];
      siteInfo.authenticationMethods.push(...matches.slice(0, 3));
    });

    // Look for rate limiting information
    const rateLimitPatterns = [
      /rate limit[^.]*\./gi,
      /\d+\s*requests?\s*per\s*(second|minute|hour|day)/gi,
      /throttl[^.]*\./gi,
      /quota[^.]*\./gi
    ];

    rateLimitPatterns.forEach(pattern => {
      const matches = siteInfo.mainContent.match(pattern) || [];
      siteInfo.rateLimits.push(...matches.slice(0, 5));
    });

    // Look for SDK information
    const sdkKeywords = ['sdk', 'client library', 'npm install', 'pip install', 'gem install'];
    sdkKeywords.forEach(keyword => {
      const regex = new RegExp(`${keyword}[^.]*\\.`, 'gi');
      const matches = siteInfo.mainContent.match(regex) || [];
      siteInfo.sdks.push(...matches.slice(0, 3));
    });

    return siteInfo;
    
  } catch (error) {
    throw new Error(`Failed to analyze documentation site: ${error.message}`);
  }
}

// Enhanced AI-powered documentation simplifier
async function createIntelligentSummary(siteInfo) {
  try {
    const prompt = `
You are an expert technical writer who specializes in making complex API and service documentation accessible to business users and developers alike.

Analyze the following documentation site information and create a comprehensive, intelligent summary.

SITE INFORMATION:
Title: ${siteInfo.title}
Service Type: ${siteInfo.serviceType}
Known Service: ${siteInfo.knownService || 'Unknown'}
URL: ${siteInfo.url}

Description: ${siteInfo.description}

Key Topics: ${siteInfo.keyTopics.slice(0, 20).join(', ')}

Navigation Structure: ${siteInfo.navigationStructure.slice(0, 15).map(nav => nav.text).join(', ')}

API Endpoints Found: ${siteInfo.apiEndpoints.slice(0, 10).join(', ')}

Authentication Methods: ${siteInfo.authenticationMethods.join(' ')}

Rate Limits: ${siteInfo.rateLimits.join(' ')}

SDK Information: ${siteInfo.sdks.join(' ')}

Main Content Sample: ${siteInfo.mainContent.substring(0, 3000)}

INSTRUCTIONS:
Create a comprehensive summary using HTML formatting with these sections:

1. **Service Overview** - What this service/API does in simple terms
2. **Key Capabilities** - Main features and what you can build with it
3. **Getting Started** - How developers typically begin using this service
4. **Authentication & Security** - How to authenticate and any security considerations
5. **Rate Limits & Quotas** - Any usage limits or restrictions
6. **Popular Use Cases** - Common ways this service is used
7. **Developer Resources** - SDKs, libraries, and tools available
8. **Important Considerations** - Things developers should know

Use HTML tags for formatting:
- <h3> for section headings
- <strong> for emphasis
- <ul> and <li> for lists
- <p> for paragraphs
- <code> for technical terms
- <blockquote> for important notes

Make it comprehensive but accessible - explain technical concepts in business terms when possible.
If this is a known service like Apollo GraphQL, include specific insights about that platform.
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4", // Using GPT-4 for better analysis
      messages: [
        {
          role: "system",
          content: "You are an expert technical documentation analyst who creates comprehensive, business-friendly summaries of complex API and service documentation."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 2000,
      temperature: 0.3
    });

    return response.choices[0].message.content;
  } catch (error) {
    throw new Error(`Failed to create intelligent summary: ${error.message}`);
  }
}