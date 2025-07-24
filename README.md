# 🚀 ZARVER Backend API

ZARVER uygulamasının FastAPI backend servisi.

## 🌐 Live API

**Railway**: [Buraya deploy URL'iniz gelecek]

## 🛠️ Tech Stack

- **FastAPI** - Modern Python web framework
- **MongoDB** - NoSQL database
- **JWT** - Authentication
- **Google Gemini AI** - Decision alternatives generation
- **WebSocket** - Real-time features

## 📦 Local Development

```bash
# Dependencies yükle
pip install -r requirements.txt

# Environment variables ayarla
cp .env.production .env
# .env dosyasını düzenleyin

# Serveri başlat
python server.py
```

API `http://localhost:8001` adresinde çalışacak.

## 🚀 Railway Deployment

### 1. Railway Setup
1. [Railway.app](https://railway.app) hesabı oluşturun
2. "New Project" → "Deploy from GitHub repo"
3. Bu repository'yi seçin

### 2. Environment Variables
Railway dashboard'da şu environment variables'ları ekleyin:

```bash
# MongoDB URL (Railway otomatik sağlar veya manuel)
MONGO_URL=mongodb://localhost:27017

# Google Gemini API Key
GEMINI_API_KEY=your-gemini-api-key-here

# JWT Secret (güçlü bir key kullanın)
JWT_SECRET=your-super-secret-jwt-key-2024

# Admin Credentials (güçlü şifreler kullanın)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-admin-password

# Port (Railway otomatik ayarlar)
PORT=8001
```

### 3. MongoDB Service
Railway'de MongoDB eklemek için:
1. "Add service" → "Database" → "MongoDB"
2. Otomatik olarak `MONGO_URL` environment variable oluşturulur

### 4. Deploy
- Push yaptığınızda otomatik deploy olur
- `https://your-app.railway.app` URL'ini alacaksınız

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/register` - Kullanıcı kaydı
- `POST /api/auth/login` - Kullanıcı girişi
- `POST /api/auth/admin/login` - Admin girişi
- `GET /api/auth/me` - Kullanıcı bilgileri

### Decisions
- `POST /api/decisions/create` - Karar oluştur
- `POST /api/decisions/{id}/roll` - Zar at
- `POST /api/decisions/{id}/implement` - Karar uygulandı işaretle
- `GET /api/decisions/history` - Karar geçmişi

### Admin
- `GET /api/admin/dashboard` - Dashboard istatistikleri
- `GET /api/admin/users` - Kullanıcı listesi
- `POST /api/admin/users/{id}/suspend` - Kullanıcıyı askıya al
- `GET /api/admin/logs` - Admin işlem logları

## 🔒 Security

- JWT token authentication
- CORS protection
- Input validation
- Admin action logging
- Privacy compliance (KVKK)

## 📁 Project Structure

```
backend/
├── server.py              # Main FastAPI application
├── requirements.txt       # Python dependencies
├── .env.production       # Environment template
├── railway.json          # Railway configuration
└── README.md            # This file
```

## 🔧 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_URL` | MongoDB connection string | `mongodb://localhost:27017` |
| `GEMINI_API_KEY` | Google Gemini API key | `AIzaSy...` |
| `JWT_SECRET` | JWT secret key | `your-secret-key` |
| `ADMIN_USERNAME` | Admin username | `admin` |
| `ADMIN_PASSWORD` | Admin password | `secure-password` |
| `PORT` | Server port | `8001` |

## 🐛 Troubleshooting

### CORS Issues
Frontend URL'inizi backend CORS ayarlarına ekleyin.

### MongoDB Connection
Railway MongoDB service'inin çalıştığından emin olun.

### Environment Variables
Tüm gerekli environment variables'ların tanımlandığından emin olun.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.