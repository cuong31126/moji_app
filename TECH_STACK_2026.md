# 🌍 EcoMoji Chat App - Tech Stack & Architecture 2026

## 📌 Project Overview
**EcoMoji** là một ứng dụng chat realtime kết hợp thu gom thông báo rác trên cả nước, giúp cộng đồng báo cáo các điểm rác công cộng để có thể được dọn dẹp và bảo vệ môi trường xanh.

---

## 🛠️ TECH STACK DETAIL

### **BACKEND STACK**

#### Core Framework
| Tech | Version | Purpose |
|------|---------|---------|
| **Node.js** | 20+ | JavaScript runtime |
| **Express.js** | 5.1.0 | Web framework |
| **Swagger UI** | 5.0.1 | API documentation |

#### Database & ORM
| Tech | Version | Purpose |
|------|---------|---------|
| **MongoDB** | 8.19 | NoSQL database |
| **Mongoose** | 8.19.0 | MongoDB ORM |

#### Authentication & Security
| Tech | Version | Purpose |
|------|---------|---------|
| **JWT (jsonwebtoken)** | 9.0.2 | Token-based auth |
| **Passport.js** | 0.7.0 | Multi-strategy auth |
| **passport-google-oauth20** | 2.0.0 | Google OAuth |
| **passport-github2** | 0.1.12 | GitHub OAuth |
| **passport-facebook** | 3.0.0 | Facebook OAuth |
| **bcrypt** | 6.0.0 | Password hashing |
| **cookie-parser** | 1.4.7 | Cookie parsing |
| **cors** | 2.8.5 | Cross-origin requests |

#### Real-time Communication
| Tech | Version | Purpose |
|------|---------|---------|
| **Socket.io** | 4.8.1 | WebSocket realtime events |

#### File & Media Management
| Tech | Version | Purpose |
|------|---------|---------|
| **Cloudinary** | 2.8.0 | Cloud image storage |
| **multer** | 2.0.2 | File upload middleware |

#### Utilities
| Tech | Version | Purpose |
|------|---------|---------|
| **dotenv** | 17.2.3 | Environment variables |
| **nodemon** | 3.1.10 | Dev server auto-reload |

---

### **FRONTEND STACK**

#### Core Framework & Build
| Tech | Version | Purpose |
|------|---------|---------|
| **React** | 19.2.0 | UI library |
| **React DOM** | 19.2.0 | React rendering |
| **Vite** | 7.2.4 | Build tool & dev server |
| **TypeScript** | ~5.9.3 | Type-safe JavaScript |

#### State Management & HTTP
| Tech | Version | Purpose |
|------|---------|---------|
| **Zustand** | 5.0.9 | Lightweight state management |
| **Axios** | 1.13.2 | HTTP client |
| **Socket.io-client** | 4.8.3 | Realtime client |

#### UI Framework & Styling
| Tech | Version | Purpose |
|------|---------|---------|
| **Tailwind CSS** | 4.1.18 | Utility-first CSS |
| **@tailwindcss/vite** | 4.1.18 | Vite plugin for Tailwind |
| **tailwind-merge** | 3.4.0 | Merge Tailwind classes |
| **tailwindcss-animate** | 1.0.7 | Animation utilities |

#### UI Components (Radix UI)
| Tech | Version | Purpose |
|------|---------|---------|
| **@radix-ui/react-avatar** | 1.1.11 | Avatar component |
| **@radix-ui/react-dialog** | 1.1.15 | Modal/Dialog |
| **@radix-ui/react-dropdown-menu** | 2.1.16 | Dropdown menu |
| **@radix-ui/react-label** | 2.1.8 | Form label |
| **@radix-ui/react-popover** | 1.1.15 | Popover tooltips |
| **@radix-ui/react-tabs** | 1.1.13 | Tab navigation |
| **@radix-ui/react-tooltip** | 1.2.8 | Tooltips |
| **@radix-ui/react-switch** | 1.2.6 | Toggle switch |
| **@radix-ui/react-separator** | 1.1.8 | Visual separator |
| **@radix-ui/react-collapsible** | 1.1.12 | Collapsible sections |

#### Icons & Emoji
| Tech | Version | Purpose |
|------|---------|---------|
| **lucide-react** | 0.562.0 | Icon library |
| **emoji-mart** | 5.6.0 | Emoji picker |
| **@emoji-mart/react** | 1.1.1 | React emoji picker |
| **@emoji-mart/data** | 1.2.1 | Emoji data |

#### Forms & Validation
| Tech | Version | Purpose |
|------|---------|---------|
| **react-hook-form** | 7.69.0 | Form state management |
| **@hookform/resolvers** | 5.2.2 | Form validation resolvers |
| **zod** | 4.2.1 | Schema validation |

#### Maps
| Tech | Version | Purpose |
|------|---------|---------|
| **leaflet** | 1.9.4 | Mapping library |
| **react-leaflet** | 5.0.0 | React wrapper for Leaflet |

#### Routing & Navigation
| Tech | Version | Purpose |
|------|---------|---------|
| **react-router** | 7.11.0 | Client-side routing |

#### Notifications & UX
| Tech | Version | Purpose |
|------|---------|---------|
| **sonner** | 2.0.7 | Toast notifications |
| **react-infinite-scroll-component** | 6.1.1 | Infinite scroll |

#### Utilities
| Tech | Version | Purpose |
|------|---------|---------|
| **class-variance-authority** | 0.7.1 | Component variants |
| **clsx** | 2.1.1 | Class name utilities |

#### Dev Tools
| Tech | Version | Purpose |
|------|---------|---------|
| **ESLint** | 9.39.1 | Code linting |
| **typescript-eslint** | 8.46.4 | TypeScript linting |
| **@vitejs/plugin-react** | 5.1.1 | Vite React plugin |

---

## 📊 DATABASE SCHEMA

### **Collections**

#### 1. **User**
```javascript
{
  username: String (unique, lowercase),
  email: String (unique, lowercase),
  displayName: String,
  hashedPassword: String (optional for OAuth users),
  avatarUrl: String (Cloudinary URL),
  avatarId: String (Cloudinary ID),
  bio: String (max 500 chars),
  phone: String (optional),
  authProviders: Array<{
    provider: "local" | "google" | "github" | "facebook",
    providerId: String
  }>,
  createdAt: Date,
  updatedAt: Date
}
```

#### 2. **Session**
```javascript
{
  userId: ObjectId (ref: User),
  refreshToken: String (unique),
  expiresAt: Date (TTL index),
  createdAt: Date,
  updatedAt: Date
}
```

#### 3. **Conversation**
```javascript
{
  type: "direct" | "group",
  participants: Array<{
    userId: ObjectId (ref: User),
    joinedAt: Date
  }>,
  group: {
    name: String,
    createdBy: ObjectId (ref: User)
  },
  lastMessageAt: Date,
  seenBy: Array<ObjectId> (ref: User),
  lastMessage: {
    _id: String,
    content: String,
    senderId: ObjectId (ref: User),
    createdAt: Date
  },
  unreadCounts: Map<userId, count>,
  createdAt: Date,
  updatedAt: Date
}
```

#### 4. **Message**
```javascript
{
  conversationId: ObjectId (ref: Conversation, indexed),
  senderId: ObjectId (ref: User),
  content: String,
  imgUrl: String (Cloudinary URL),
  messageType: "text" | "image" | "trash_report" | "system",
  trashReport: ObjectId (ref: TrashReport, optional),
  isRevoked: Boolean,
  revokedAt: Date,
  createdAt: Date,
  updatedAt: Date
}
```

#### 5. **TrashReport**
```javascript
{
  title: String (max 120 chars),
  description: String,
  type: "plastic" | "organic" | "metal" | "glass" | "other",
  severity: "low" | "medium" | "high",
  status: "ACTIVE" | "VERIFIED" | "CLEANUP_PENDING" | "CLEANED",
  location: {
    type: "Point" (GeoJSON),
    coordinates: [lng, lat],
    lat: Number,
    lng: Number,
    address: String
  },
  reportedBy: ObjectId (ref: User),
  images: Array<String> (Cloudinary URLs),
  views: Array<ObjectId> (ref: User),
  confirmations: Array<{
    userId: ObjectId (ref: User),
    createdAt: Date
  }>,
  cleanup: {
    cleanedBy: ObjectId (ref: User),
    beforeImages: Array<String>,
    afterImages: Array<String>,
    description: String,
    createdAt: Date
  },
  createdAt: Date,
  updatedAt: Date
}
```

#### 6. **Friend & FriendRequest**
```javascript
// Friend
{
  userId1: ObjectId (ref: User),
  userId2: ObjectId (ref: User),
  createdAt: Date
}

// FriendRequest
{
  sender: ObjectId (ref: User),
  receiver: ObjectId (ref: User),
  status: "pending" | "accepted" | "rejected",
  createdAt: Date
}
```

---

## 🔄 REAL-TIME EVENTS (Socket.io)

### **From Server to Client**
```javascript
// User status
"online-users" → Array<userId>

// Chat messages
"new-message" → Message object
"message-updated" → Updated message
"message-revoked" → {messageId, revokedAt}

// Typing indicators
"user-typing" → {userId, conversationId}
"user-stopped-typing" → {userId, conversationId}

// Conversation updates
"conversation-updated" → Conversation object
"message-seen" → {conversationId, seenBy}

// Notifications
"notification" → {type, data}
```

### **From Client to Server**
```javascript
"join-conversation" → conversationId
"send-message" → Message object
"revoke-message" → messageId
"user-typing" → conversationId
"mark-seen" → conversationId
```

---

## 🏗️ PROJECT DIRECTORY STRUCTURE

```
moji/
├── backend/
│   ├── src/
│   │   ├── server.js                 # Entry point
│   │   ├── config/
│   │   │   └── passport.js           # OAuth strategies
│   │   ├── controllers/
│   │   │   ├── authController.js     # Auth logic
│   │   │   ├── userController.js
│   │   │   ├── conversationController.js
│   │   │   ├── messageController.js
│   │   │   ├── friendController.js
│   │   │   ├── reportController.js
│   │   │   └── chatController.js
│   │   ├── models/
│   │   │   ├── User.js
│   │   │   ├── Session.js
│   │   │   ├── Conversation.js
│   │   │   ├── Message.js
│   │   │   ├── TrashReport.js
│   │   │   ├── Friend.js
│   │   │   ├── FriendRequest.js
│   │   │   └── TrashComment.js
│   │   ├── routes/
│   │   │   ├── authRoute.js
│   │   │   ├── userRoute.js
│   │   │   ├── conversationRoute.js
│   │   │   ├── messageRoute.js
│   │   │   ├── friendRoute.js
│   │   │   └── reportRoute.js
│   │   ├── middlewares/
│   │   │   ├── authMiddleware.js     # Verify JWT
│   │   │   ├── socketMiddleware.js   # Socket auth
│   │   │   ├── uploadMiddleware.js   # File upload
│   │   │   └── friendMiddleware.js
│   │   ├── socket/
│   │   │   └── index.js              # Socket.io setup
│   │   ├── utils/
│   │   │   ├── authHelper.js         # JWT helpers
│   │   │   ├── socialAuth.js         # OAuth user creation
│   │   │   └── messageHelper.js
│   │   ├── libs/
│   │   │   └── db.js                 # MongoDB connection
│   │   └── swagger.json              # API docs
│   ├── package.json
│   └── .env (example below)
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx                  # Entry point
│   │   ├── App.tsx
│   │   ├── App.css
│   │   ├── index.css                 # Global styles
│   │   ├── pages/
│   │   │   ├── ChatAppPage.tsx       # Main chat interface
│   │   │   ├── SignInPage.tsx
│   │   │   ├── SignUpPage.tsx
│   │   │   └── SocialCallbackPage.tsx
│   │   ├── components/
│   │   │   ├── auth/
│   │   │   │   ├── signin-form.tsx
│   │   │   │   ├── signup-form.tsx
│   │   │   │   ├── ProtectedRoute.tsx
│   │   │   │   ├── AuthThemeToggle.tsx
│   │   │   │   └── Logout.tsx
│   │   │   ├── chat/
│   │   │   │   ├── ChatWindowLayout.tsx
│   │   │   │   ├── ChatWindowHeader.tsx
│   │   │   │   ├── ChatWindowBody.tsx
│   │   │   │   ├── ChatCard.tsx      # Conversation list
│   │   │   │   ├── DirectMessageCard.tsx
│   │   │   │   ├── GroupChatCard.tsx
│   │   │   │   ├── DirectMessageList.tsx
│   │   │   │   ├── UserAvatar.tsx
│   │   │   │   ├── EmojiPicker.tsx
│   │   │   │   ├── ChatWelcomeScreen.tsx
│   │   │   │   ├── CreateNewChat.tsx
│   │   │   │   └── GroupChatAvatar.tsx
│   │   │   ├── profile/
│   │   │   │   ├── ProfileCard.tsx
│   │   │   │   ├── ProfileDialog.tsx
│   │   │   │   ├── AvatarUploader.tsx
│   │   │   │   ├── PersonalInfoForm.tsx
│   │   │   │   ├── PreferencesForm.tsx
│   │   │   │   └── PrivacySettings.tsx
│   │   │   ├── friendRequest/
│   │   │   ├── AddFriendModal/
│   │   │   ├── map/
│   │   │   ├── newGroupChat/
│   │   │   ├── sidebar/
│   │   │   ├── skeleton/ (loading placeholders)
│   │   │   └── ui/ (Radix UI wrappers)
│   │   ├── services/
│   │   │   ├── authService.ts        # Auth API calls
│   │   │   ├── chatService.ts
│   │   │   ├── friendService.ts
│   │   │   ├── userService.ts
│   │   │   └── reportService.ts
│   │   ├── stores/
│   │   │   ├── useAuthStore.ts       # Auth state
│   │   │   ├── useChatStore.ts       # Chat state
│   │   │   ├── useFriendStore.ts
│   │   │   ├── useSocketStore.ts     # Socket state
│   │   │   ├── useThemeStore.ts      # Dark/light mode
│   │   │   └── useUserStore.ts       # User profile state
│   │   ├── types/
│   │   │   ├── chat.ts
│   │   │   ├── user.ts
│   │   │   ├── report.ts
│   │   │   └── store.ts
│   │   ├── lib/
│   │   │   ├── axios.ts              # Axios config + interceptors
│   │   │   └── utils.ts
│   │   ├── hooks/
│   │   │   └── use-mobile.ts
│   │   ├── assets/ (images, icons)
│   │   └── public/
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   ├── package.json
│   └── index.html
│
└── .env (root)
```

---

## 🎨 UI COMPONENTS & DESIGN SYSTEM

### **Color Scheme**
- **Primary**: Emerald/Teal (eco-friendly theme)
- **Accent**: Sky blue
- **Neutral**: Gray scale for text
- **Dark Mode**: Slate 900 background
- **Light Mode**: White/Gray background

### **Component Library**
- **Radix UI**: Accessible, headless components
- **Tailwind CSS**: Utility-first styling
- **Lucide Icons**: 562 consistent icons
- **Emoji Mart**: Full emoji picker

### **Key UI Patterns**
```
Layout Structure:
┌─────────────────────────────────────────┐
│     Header (navbar, user menu)          │
├──────────────┬──────────────────────────┤
│   Sidebar    │   Main Content Area      │
│   - Chats    │   ├─ ChatWindow         │
│   - Friends  │   ├─ Messages           │
│   - Map      │   └─ Compose            │
│   - Profile  │                          │
└──────────────┴──────────────────────────┘

Chat Message Bubble:
┌─────────────────────────────┐
│ [Avatar] User Name          │
│                              │
│ Message content with emoji  │
│ and optional images         │
│                              │
│ Timestamp  [Seen] [Delete]  │
└─────────────────────────────┘

Trash Report Card:
┌─────────────────────────────┐
│ [Map Image] Severity Badge  │
│ Title                       │
│ Location, Type              │
│ Status: ACTIVE/CLEANED      │
│ Confirmations: 12 users     │
│ [View] [Confirm] [Clean]    │
└─────────────────────────────┘
```

---

## 🔐 Authentication Flow

```
┌─────────────────────────────────────────────────────────┐
│  LOCAL AUTHENTICATION                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. User SignUp                                        │
│     POST /api/auth/signup                             │
│     {username, email, password, firstName, lastName}  │
│                                                         │
│  2. User SignIn                                        │
│     POST /api/auth/signin                             │
│     {username, password}                              │
│     → Response: {accessToken, user}                   │
│     → Set: httpOnly cookie (refreshToken)            │
│                                                         │
│  3. Token Refresh                                      │
│     POST /api/auth/refresh                            │
│     Cookie: refreshToken                              │
│     → Response: {accessToken, user}                   │
│                                                         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  OAUTH AUTHENTICATION                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. User clicks "Continue with Google/GitHub/FB"      │
│     window.location.href = /api/auth/[provider]      │
│                                                         │
│  2. OAuth Provider Redirect                           │
│     Google/GitHub/Facebook OAuth flow                │
│                                                         │
│  3. Callback Handler                                   │
│     GET /api/auth/[provider]/callback                │
│     Passport verifies → findOrCreateSocialUser       │
│     → Set: httpOnly cookie (refreshToken)            │
│     → Redirect: /auth/social-callback                │
│                                                         │
│  4. Frontend Refresh                                   │
│     SocialCallbackPage calls refresh()               │
│     POST /api/auth/refresh                            │
│     → Get accessToken + user info                    │
│     → Navigate to /                                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📡 API ENDPOINTS

### **Auth Routes** (`/api/auth`)
```
POST   /signup              Create new account
POST   /signin              Login with username/password
POST   /signout             Logout & clear session
POST   /refresh             Get new access token
GET    /google              Initiate Google OAuth
GET    /google/callback     Google OAuth callback
GET    /github              Initiate GitHub OAuth
GET    /github/callback     GitHub OAuth callback
GET    /facebook            Initiate Facebook OAuth
GET    /facebook/callback   Facebook OAuth callback
```

### **User Routes** (`/api/users`)
```
GET    /me                  Get current user
GET    /:id                 Get user by ID
PATCH  /:id                 Update user profile
PUT    /:id/avatar          Upload avatar
```

### **Conversation Routes** (`/api/conversations`)
```
GET    /                    Get all conversations
POST   /                    Create new conversation
GET    /:id                 Get conversation details
GET    /:id/messages        Get messages (paginated)
PUT    /:id                 Update conversation
```

### **Message Routes** (`/api/messages`)
```
POST   /                    Send message
DELETE /:id                 Revoke message
PUT    /:id                 Edit message
```

### **Friend Routes** (`/api/friends`)
```
GET    /requests            Get friend requests
POST   /request             Send friend request
PATCH  /request/:id/accept  Accept friend request
DELETE /request/:id         Reject friend request
DELETE /:id                 Remove friend
GET    /                    Get friends list
```

### **Report Routes** (`/api/reports`)
```
GET    /                    Get all trash reports
POST   /                    Create trash report
GET    /:id                 Get report details
PATCH  /:id                 Update report
DELETE /:id                 Delete report
POST   /:id/confirm         Confirm report
POST   /:id/cleanup         Mark as cleaned
```

---

## 🌐 Environment Variables

### **.env (Backend)**
```
# Server
NODE_ENV=development
PORT=5001
SERVER_URL=http://localhost:5001
CLIENT_URL=http://localhost:5173

# Database
MONGODB_URI=mongodb://localhost:27017/ecomoji

# JWT
ACCESS_TOKEN_SECRET=your_secret_key_here
REFRESH_TOKEN_SECRET=your_refresh_secret_key

# OAuth - Google
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:5001/api/auth/google/callback

# OAuth - GitHub
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_CALLBACK_URL=http://localhost:5001/api/auth/github/callback

# OAuth - Facebook
FACEBOOK_CLIENT_ID=your_facebook_app_id
FACEBOOK_CLIENT_SECRET=your_facebook_app_secret
FACEBOOK_CALLBACK_URL=http://localhost:5001/api/auth/facebook/callback

# Cloudinary
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

# Gemini AI (Optional for smart reply)
GEMINI_API_KEY=your_gemini_api_key
```

### **.env (Frontend)**
```
VITE_API_URL=http://localhost:5001/api
VITE_SOCKET_URL=http://localhost:5001
```

---

## 🚀 DEVELOPMENT WORKFLOW

### **Setup & Installation**
```bash
# Clone & install dependencies
git clone <repo>
cd moji

# Backend setup
cd backend
npm install
npm run dev

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### **Build & Deploy**
```bash
# Frontend build
npm run build              # Compile TS + bundle
npm run preview           # Preview production build
npm run lint              # Check code quality

# Backend production
npm run start             # Run production server
```

---

## 📈 SCALABILITY & PERFORMANCE

### **Frontend Optimizations**
- Vite fast HMR (Hot Module Replacement)
- Code splitting via React Router
- Lazy loading components
- Infinite scroll for messages
- Skeleton loading screens

### **Backend Optimizations**
- MongoDB indexing (userId, conversationId, timestamps)
- Socket.io room-based communication
- Message pagination
- Connection pooling (Mongoose)

### **Database Indexing**
```javascript
// User indexes
unique: [username, email]

// Conversation indexes
"participants.userId" + "lastMessageAt"

// Message indexes
"conversationId" + "createdAt"

// TrashReport indexes
"location" (GeoSpatial)
"status"
"reportedBy"

// Session indexes
"expiresAt" (TTL auto-delete)
```

---

## 🎯 CURRENT FEATURES STATUS

| Feature | Status | Priority |
|---------|--------|----------|
| **Local Auth** | ✅ Complete | High |
| **OAuth (Google/GitHub/Facebook)** | ✅ 95% (callback fix needed) | High |
| **Direct Messages** | ✅ Complete | High |
| **Group Chat** | ✅ Complete | High |
| **Real-time Socket.io** | ✅ Complete | High |
| **Friend Management** | ✅ Complete | High |
| **Trash Reports** | ✅ Complete | High |
| **Geo-location Map** | ✅ Complete | High |
| **Avatar Upload** | ✅ Complete (UI fix needed) | Medium |
| **Theme Dark/Light** | ✅ Complete | Medium |
| **Emoji Picker** | ✅ Complete | Medium |
| **Session Expiry** | ⚠️ Needs fix | Critical |
| **AI Smart Reply** | ❌ Not started | Low |
| **Message Search** | ❌ Not started | Medium |
| **File Sharing** | ❌ Not started | Low |

---

## 🔧 MAINTENANCE & UPDATES

### **Recommended Regular Updates**
- Node.js: Keep on v20+ LTS
- Dependencies: Monthly security audits
- MongoDB: Backup strategy
- Cloudinary: Monitor API usage

### **Known Issues to Fix**
1. Session expiry loop (Bước 1 roadmap)
2. OAuth callback return accessToken (Bước 2-3 roadmap)
3. Avatar PNG white background on dark mode (Bước 5 roadmap)
4. Axios interceptor timeout handling (Bước 1 roadmap)

---

## 📚 USEFUL COMMANDS

```bash
# Development
npm run dev                 # Start dev server with auto-reload
npm run lint               # Check code style
npm run build              # Production build

# Database
# Connect to MongoDB
mongosh "mongodb://localhost:27017/ecomoji"

# Clean Docker (if using)
docker-compose down -v

# API Documentation
# Visit http://localhost:5001/api-docs

# Socket.io Debugging
# Visit http://localhost:5001/socket.io/debug
```

---

**Last Updated:** April 29, 2026  
**Version:** 1.0.0  
**Team:** UTE - EcoMoji Development Team
