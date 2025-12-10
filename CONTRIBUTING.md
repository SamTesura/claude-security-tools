# Contributing to Claude Security Tools

Thank you for your interest in contributing to Claude Security Tools! This document provides guidelines for contributing to this project.

## 📜 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback  
- Remember this is an educational security tool - use responsibly
- Follow ethical hacking principles

## 🤝 How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/samtesura/claude-security-tools/issues)
2. If not, create a new issue with:
   - **Clear title and description**
   - **Steps to reproduce** the bug
   - **Expected vs actual behavior**
   - **Your environment** (Windows version, WSL version, Docker version)
   - **Relevant logs or error messages**

### Suggesting Features

1. Open an issue with the **"enhancement"** label
2. Describe the feature clearly
3. Explain the use case
4. Describe why it would be useful to the community

### Submitting Pull Requests

1. **Fork the repository**
2. **Create a new branch** (`git checkout -b feature/your-feature-name`)
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**
6. **Push to your fork**
7. **Open a Pull Request** with a clear description

## 💻 Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/claude-security-tools.git
cd claude-security-tools

# Create feature branch
git checkout -b feature/your-feature

# Make changes and test
docker-compose build --no-cache
docker-compose up -d

# Commit and push
git add .
git commit -m "Add: your feature description"
git push origin feature/your-feature
```

## 📝 Code Style

### Python

- Follow **PEP 8** style guide
- Use **type hints** where possible
- Add **docstrings** for functions
- Keep functions **focused and small**

### Shell Scripts

- Use **shellcheck** for validation
- Add comments for complex logic
- Use `set -e` for error handling

### Docker

- Follow **Dockerfile best practices**
- Minimize layers
- Use specific versions
- Add comments

## 🔒 Security Considerations

- **Never commit** sensitive data
- **Sanitize all inputs**
- **Validate** user-provided data
- **Use least privilege** principle
- **Document security implications**

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing!** 🚀
