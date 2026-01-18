# Contributing to sdbx

Thanks for your interest! 🎉

## 🤝 How to Contribute

**Ways to help:**
- 🐛 Report bugs via [issues](https://github.com/antonaks/sdbx/issues)
- 💡 Suggest features
- 📚 Improve docs
- 🧪 Add tests
- 💻 Fix bugs or add features

**For security issues:** See [SECURITY.md](./SECURITY.md)

---

## 🚀 Quick Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/sdbx.git
cd sdbx

# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-test.txt
pytest

# Frontend  
npm install
npm run build:css
cd frontend && node --test tests/*.test.js
```

---

## 📝 Workflow

1. **Create branch:** `git checkout -b fix/your-fix`
2. **Make changes** + add tests
3. **Run tests:** `make test`
4. **Commit:** `git commit -m "fix: describe change"`
5. **Push:** `git push origin fix/your-fix`
6. **Open PR** on GitHub

**Commit format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring

---

## ✅ Before Submitting PR

- [ ] Tests pass
- [ ] Code follows existing style
- [ ] Documentation updated (if needed)
- [ ] Clear commit messages

---

## 📏 Code Style

**Python:** Use `black` and `isort`
```bash
cd backend
black lambdas/ shared/
isort lambdas/ shared/
```

**JavaScript:** Clear code, JSDoc comments, `'use strict'`

---

## 🧪 Testing

- Add tests for new code
- All tests must pass
- Aim for 80%+ coverage

```bash
make test              # All tests
make test-backend      # Backend only
make test-frontend     # Frontend only
```

---

## 🔒 Security

**Critical:** Changes to `frontend/js/crypto.js` need extra review
- Discuss in issue first
- Add comprehensive tests
- Expect thorough code review

---

## 🎯 Good First Issues

Look for [`good first issue`](https://github.com/antonaks/sdbx/labels/good%20first%20issue) label:
- Fix typos
- Add tests
- Improve docs
- Small bug fixes

---

## ❓ Questions?

- Open an [issue](https://github.com/antonaks/sdbx/issues)
- Check [README](./README.md), [SECURITY.md](./SECURITY.md), [ROADMAP.md](./ROADMAP.md)

---

**Thank you for contributing!** 🚀
