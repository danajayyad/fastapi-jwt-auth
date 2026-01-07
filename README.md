# FastAPI JWT Authentication Example

> ⚠️ **Note:** This project is still under development and may change. Use it for learning and experimentation only.

This project demonstrates a basic JWT-based authentication system using **FastAPI**, **Python-JOSE**, and **Passlib** for secure password hashing.

## Features

- User authentication with **username and password**
- **JWT token generation** with expiration
- **Token verification** including signature and expiration checks
- Secure password hashing with **bcrypt**
- Stateless, scalable authentication (no server-side session storage)

## Requirements

- Python 3.9+
- FastAPI
- Uvicorn
- python-jose
- passlib[bcrypt]
- python-dotenv (for loading secret keys from `.env`)

Install dependencies:

```bash
pip install fastapi uvicorn python-jose passlib[bcrypt] python-dotenv
