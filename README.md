# API Doc Simplifier

A powerful tool that transforms complex API documentation (OpenAPI/Swagger) into simple, understandable explanations for non-technical users using AI.

## 🌟 Features

- **Multiple Input Methods**: Upload files, paste URLs, or input raw content
- **AI-Powered Simplification**: Uses OpenAI GPT-4 to create user-friendly explanations
- **Support for Multiple Formats**: JSON, YAML, and YML files
- **Beautiful Modern UI**: Clean, responsive interface with drag-and-drop functionality
- **Comprehensive Analysis**: Extracts key information like endpoints, methods, and API structure
- **Real-time Processing**: Fast processing with loading indicators and error handling

## 🚀 Quick Start

### Prerequisites

- Node.js (v14 or higher)
- OpenAI API key

### Installation

1. **Clone or download the project**
   ```bash
   git clone <your-repo-url>
   cd api-doc-simplifier
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp env.example .env
   ```
   
   Edit `.env` and add your OpenAI API key:
   ```
   OPENAI_API_KEY=your_openai_api_key_here
   PORT=3000
   ```

4. **Start the application**
   ```bash
   npm start
   ```
   
   For development with auto-restart:
   ```bash
   npm run dev
   ```

5. **Open your browser**
   Navigate to `http://localhost:3000`

## 🎯 How to Use

### Method 1: File Upload
1. Click on the "Upload File" card
2. Drag and drop or click to select your OpenAPI/Swagger file (.json, .yaml, .yml)
3. Click "Simplify Documentation"

### Method 2: URL Input
1. Click on the "From URL" card
2. Enter the URL to your API documentation
3. Click "Simplify Documentation"

### Method 3: Raw Content
1. Click on the "Paste Content" card
2. Select the format (JSON or YAML)
3. Paste your API documentation content
4. Click "Simplify Documentation"

## 📁 Project Structure

```
api-doc-simplifier/
├── server.js              # Main Express server
├── package.json           # Dependencies and scripts
├── env.example           # Environment variables template
├── README.md             # This file
├── public/
│   └── index.html        # Frontend interface
└── uploads/              # Temporary file storage (auto-created)
```

## 🔧 API Endpoints

- `GET /` - Serve the main application
- `POST /api/upload` - Process uploaded API documentation files
- `POST /api/process-url` - Process API documentation from URL
- `POST /api/process-raw` - Process raw API documentation content
- `GET /api/health` - Health check endpoint

## 🛠️ Technologies Used

- **Backend**: Node.js, Express.js
- **AI**: OpenAI GPT-4
- **API Parsing**: Swagger Parser
- **File Handling**: Multer
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **Styling**: Modern CSS with gradients and animations

## 🔒 Security Features

- File type validation (only JSON, YAML, YML allowed)
- File size limits
- Automatic cleanup of uploaded files
- Input validation and sanitization
- Error handling and logging

## 🎨 UI Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Drag & Drop**: Easy file uploading
- **Loading States**: Visual feedback during processing
- **Error Handling**: Clear error messages
- **Modern Styling**: Beautiful gradients and animations
- **Accessibility**: Keyboard navigation and screen reader friendly

## 🚨 Troubleshooting

### Common Issues

1. **"OPENAI_API_KEY not found" warning**
   - Make sure you've created a `.env` file with your OpenAI API key

2. **File upload not working**
   - Check that your file is in JSON, YAML, or YML format
   - Ensure the file contains valid OpenAPI/Swagger documentation

3. **URL processing fails**
   - Verify the URL is accessible and returns valid API documentation
   - Check if the URL requires authentication

4. **Processing takes too long**
   - Large API documentation files may take longer to process
   - Check your internet connection for OpenAI API calls

### Error Messages

- **"Failed to parse API document"**: Your file format is invalid or corrupted
- **"Failed to simplify API documentation"**: Issue with OpenAI API (check your API key and quota)
- **"Network error"**: Connection issues or server problems

## 📝 Example API Documentation

You can test the application with popular API documentation like:
- Swagger Petstore: `https://petstore.swagger.io/v2/swagger.json`
- GitHub API: `https://api.github.com/swagger.json`
- Any OpenAPI 3.0 or Swagger 2.0 specification

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues or have questions:
1. Check the troubleshooting section above
2. Review the error messages in the browser console
3. Ensure all dependencies are properly installed
4. Verify your OpenAI API key is valid and has sufficient quota

## 🔮 Future Enhancements

- Support for more API documentation formats
- Export simplified documentation to PDF/Word
- Team collaboration features
- API documentation comparison tools
- Integration with popular documentation platforms 