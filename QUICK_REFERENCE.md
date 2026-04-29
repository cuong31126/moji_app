# 🎯 EcoMoji - Quick Reference & Roadmap

## ⚡ QUICK START GUIDE

### **Setup Environment**
```bash
# 1. Clone repository
git clone <your-repo-url>
cd moji

# 2. Backend setup
cd backend
npm install
cp .env.example .env
# Edit .env with your credentials

# 3. Frontend setup (new terminal)
cd frontend
npm install
# .env setup is in vite.config.ts

# 4. Start development
# Terminal 1 - Backend
npm run dev

# Terminal 2 - Frontend
npm run dev

# Open http://localhost:5173
```

### **Environment Variables Checklist**
```
Backend .env:
□ MONGODB_URI
□ PORT (5001)
□ NODE_ENV (development)
□ CLIENT_URL (http://localhost:5173)
□ ACCESS_TOKEN_SECRET
□ REFRESH_TOKEN_SECRET
□ GOOGLE_CLIENT_ID & SECRET
□ GITHUB_CLIENT_ID & SECRET
□ FACEBOOK_CLIENT_ID & SECRET
□ CLOUDINARY_CLOUD_NAME, API_KEY, API_SECRET

Frontend .env (vite):
□ VITE_API_URL (http://localhost:5001/api)
□ VITE_SOCKET_URL (http://localhost:5001)
```

---

## 🗺️ FEATURE ROADMAP

### **Phase 1: MVP (Current - Week 1-2) ✅**
- [x] Local authentication (signup/signin)
- [x] Direct message chat
- [x] Group chat
- [x] Friend management
- [x] Real-time Socket.io
- [x] User profiles
- [x] Avatar upload
- [x] Trash report system
- [x] Map view
- [x] Dark/Light mode
- [x] Emoji picker

### **Phase 2: Auth Improvements (Week 2-3) 🔄**
- [ ] Fix session expiry bugs (Critical)
- [ ] OAuth callback return accessToken
- [ ] Google Login ✅ (95% ready)
- [ ] GitHub Login ✅ (95% ready)
- [ ] Facebook Login ✅ (95% ready)
- [ ] Email verification
- [ ] Password reset
- [ ] Two-factor authentication (TFA) optional

### **Phase 3: UX Polish (Week 3-4)**
- [ ] Fix avatar PNG dark mode
- [ ] Message search
- [ ] Message reactions (emoji)
- [ ] Message editing
- [ ] Message deletion (revoke)
- [ ] Typing indicators
- [ ] Read receipts
- [ ] Online status
- [ ] Block user functionality

### **Phase 4: AI Features (Week 4-5) 🤖**
- [ ] Smart reply suggestions (Gemini)
- [ ] Chat summarize
- [ ] Auto-translate messages
- [ ] Trash report AI summary
- [ ] Toxic message detection
- [ ] Emoji suggestions

### **Phase 5: Advanced Features (Week 5+)**
- [ ] Voice messages
- [ ] Video calls (WebRTC)
- [ ] File sharing (documents)
- [ ] Message forwarding
- [ ] Conversation archive
- [ ] Message reactions
- [ ] Trash report verification system
- [ ] Cleanup team management
- [ ] Notification system (email, SMS)
- [ ] Admin dashboard
- [ ] User analytics

### **Phase 6: Optimization & Scale (Week 6+)**
- [ ] Database indexing optimization
- [ ] Caching (Redis)
- [ ] CDN for images
- [ ] API rate limiting
- [ ] Load testing
- [ ] Security audit
- [ ] Performance monitoring
- [ ] Error tracking (Sentry)

---

## 📋 FILE STRUCTURE CHEAT SHEET

### **Backend Quick Navigation**
```
backend/src/
├── server.js                          ← Start here (entry point)
├── config/passport.js                 ← OAuth setup
├── controllers/
│   ├── authController.js              ← Login, register, OAuth
│   ├── conversationController.js       ← Chat conversations
│   ├── messageController.js            ← Message CRUD
│   ├── userController.js               ← User profile
│   ├── friendController.js             ← Friend system
│   └── reportController.js             ← Trash reports
├── routes/
│   ├── authRoute.js                   ← /api/auth endpoints
│   ├── conversationRoute.js            ← /api/conversations
│   ├── messageRoute.js                 ← /api/messages
│   └── ...
├── models/
│   ├── User.js                        ← User schema
│   ├── Conversation.js                 ← Chat conversations
│   ├── Message.js                      ← Messages
│   ├── TrashReport.js                  ← Trash reports
│   └── Session.js                      ← Auth sessions
├── middlewares/
│   ├── authMiddleware.js              ← JWT verify
│   ├── socketMiddleware.js            ← Socket auth
│   └── uploadMiddleware.js            ← File upload
├── socket/index.js                    ← Socket.io events
├── utils/
│   ├── authHelper.js                  ← JWT helpers
│   ├── socialAuth.js                  ← OAuth user creation
│   └── messageHelper.js               ← Message utilities
└── swagger.json                       ← API documentation
```

### **Frontend Quick Navigation**
```
frontend/src/
├── main.tsx                           ← React entry point
├── App.tsx                            ← Main component
├── pages/
│   ├── ChatAppPage.tsx                ← Main chat interface (START HERE)
│   ├── SignInPage.tsx                 ← Login page
│   ├── SignUpPage.tsx                 ← Register page
│   └── SocialCallbackPage.tsx         ← OAuth callback
├── components/
│   ├── auth/
│   │   ├── ProtectedRoute.tsx         ← Route guard
│   │   ├── signin-form.tsx            ← Login form (OAuth buttons)
│   │   └── signup-form.tsx            ← Register form
│   ├── chat/
│   │   ├── ChatWindowLayout.tsx       ← Main layout
│   │   ├── ChatWindowBody.tsx         ← Message list
│   │   ├── ChatCard.tsx               ← Conversation item
│   │   ├── UserAvatar.tsx             ← Avatar component (NEEDS FIX)
│   │   └── EmojiPicker.tsx            ← Emoji selector
│   ├── profile/
│   │   ├── ProfileCard.tsx            ← User profile
│   │   ├── AvatarUploader.tsx         ← Avatar upload
│   │   └── ProfileDialog.tsx          ← Profile modal
│   └── ui/                            ← Radix UI wrappers
├── stores/
│   ├── useAuthStore.ts                ← Auth state (NEEDS FIX)
│   ├── useChatStore.ts                ← Chat state
│   ├── useSocketStore.ts              ← Socket state
│   └── useUserStore.ts                ← User state
├── services/
│   ├── authService.ts                 ← Auth API
│   ├── chatService.ts                 ← Chat API
│   └── userService.ts                 ← User API
├── lib/
│   ├── axios.ts                       ← HTTP client (NEEDS FIX)
│   └── utils.ts                       ← Utilities
├── types/
│   ├── chat.ts                        ← Chat types
│   ├── user.ts                        ← User types
│   └── report.ts                      ← Report types
└── hooks/
    └── use-mobile.ts                  ← Mobile detection
```

---

## 🔄 API ENDPOINTS REFERENCE

### **Authentication (`/api/auth`)**
```
POST   /signup              Create account
POST   /signin              Login
POST   /signout             Logout
POST   /refresh             Refresh token
GET    /google              Google OAuth
GET    /google/callback     Google callback
GET    /github              GitHub OAuth
GET    /github/callback     GitHub callback
GET    /facebook            Facebook OAuth
GET    /facebook/callback   Facebook callback
```

### **Users (`/api/users`)**
```
GET    /me                  Get current user
GET    /:id                 Get user by ID
PATCH  /:id                 Update profile
PUT    /:id/avatar          Upload avatar
```

### **Conversations (`/api/conversations`)**
```
GET    /                    Get all conversations
POST   /                    Create conversation
GET    /:id                 Get conversation
GET    /:id/messages        Get messages (paginated)
PUT    /:id                 Update conversation
DELETE /:id                 Delete conversation
```

### **Messages (`/api/messages`)**
```
POST   /                    Send message
DELETE /:id                 Delete message
PUT    /:id                 Edit message
```

### **Friends (`/api/friends`)**
```
GET    /                    Get friends
POST   /request             Send friend request
PATCH  /request/:id/accept  Accept request
DELETE /request/:id         Reject request
DELETE /:id                 Remove friend
```

### **Reports (`/api/reports`)**
```
GET    /                    Get all reports
POST   /                    Create report
GET    /:id                 Get report
PATCH  /:id                 Update report
DELETE /:id                 Delete report
POST   /:id/confirm         Confirm report
POST   /:id/cleanup         Mark cleaned
```

---

## 🎨 UI COMPONENTS USAGE

### **Avatar Component**
```tsx
import UserAvatar from "@/components/chat/UserAvatar";

<UserAvatar 
  type="chat"           // "sidebar" | "chat" | "profile"
  name="Người Dùng"
  avatarUrl="https://..."
  className="ring-2 ring-border"
/>
```

### **Chat Card (Conversation)**
```tsx
import ChatCard from "@/components/chat/ChatCard";

<ChatCard 
  conversation={conversation}
  isSelected={isSelected}
  onClick={() => selectConversation(id)}
/>
```

### **Profile Dialog**
```tsx
import ProfileDialog from "@/components/profile/ProfileDialog";

<ProfileDialog user={user} open={open} onOpenChange={setOpen} />
```

### **Emoji Picker**
```tsx
import EmojiPicker from "@/components/chat/EmojiPicker";

<EmojiPicker onSelect={(emoji) => insertEmoji(emoji)} />
```

---

## 🔐 STATE MANAGEMENT PATTERN

### **Using Zustand Store**
```tsx
// Store definition (e.g., useAuthStore.ts)
import { create } from "zustand";

export const useAuthStore = create((set) => ({
  accessToken: null,
  user: null,
  
  setAccessToken: (token) => set({ accessToken: token }),
  setUser: (user) => set({ user }),
  
  signIn: async (username, password) => {
    const data = await authService.signIn(username, password);
    set({ 
      accessToken: data.accessToken,
      user: data.user 
    });
  },
}));

// Usage in components
function MyComponent() {
  const { user, signIn } = useAuthStore();
  
  return (
    <div>
      <p>Hello {user?.displayName}</p>
      <button onClick={() => signIn("user", "pass")}>Login</button>
    </div>
  );
}
```

---

## 📡 SOCKET.IO EVENTS REFERENCE

### **Client → Server Events**
```javascript
// Join conversation
socket.emit("join-conversation", conversationId);

// Send message
socket.emit("send-message", {
  conversationId,
  content,
  messageType: "text"
});

// Mark message as seen
socket.emit("mark-seen", conversationId);

// Typing indicator
socket.emit("user-typing", conversationId);
socket.emit("user-stopped-typing", conversationId);
```

### **Server → Client Events**
```javascript
// New message received
socket.on("new-message", (message) => {
  // Add to message list
  useChatStore.getState().addMessage(message);
});

// Online users updated
socket.on("online-users", (userIds) => {
  useSocketStore.getState().setOnlineUsers(userIds);
});

// Message seen
socket.on("message-seen", (data) => {
  // Update read receipts
});

// User typing
socket.on("user-typing", (data) => {
  // Show typing indicator
});
```

---

## 🐛 COMMON ISSUES & FIXES

### **Issue 1: CORS Error**
```
Error: Access to XMLHttpRequest blocked by CORS policy
Fix: 
1. Check backend CORS config: app.use(cors({ origin, credentials: true }))
2. Axios: withCredentials: true
3. Cookie: SameSite=Lax (dev) or SameSite=None (prod)
```

### **Issue 2: Socket.io Connection Fails**
```
Error: WebSocket connection failed
Fix:
1. Check SOCKET_URL in frontend
2. Verify server running: http://localhost:5001
3. Check socket middleware auth
4. Browser DevTools > Network > WS tab
```

### **Issue 3: Avatar Shows White Box on Dark Mode**
```
Error: PNG with white background looks bad
Fix:
1. Add bg-muted to UserAvatar
2. Add ring-2 ring-border
3. Cloudinary: use c_fill transformation
4. Recommend PNG transparent or JPG
```

### **Issue 4: Token Expires Silently**
```
Error: User logged out without warning
Fix:
1. Check axios interceptor (lib/axios.ts)
2. Verify refresh token cookie exists
3. Check ProtectedRoute refresh logic
4. Set timeout on refresh calls
```

### **Issue 5: Message Doesn't Send**
```
Error: Message stuck in compose
Fix:
1. Check socket connected: useSocketStore.getState().connected
2. Verify conversationId exists
3. Check network tab for errors
4. Retry mechanism in message handler
```

---

## 📊 PERFORMANCE OPTIMIZATION TIPS

### **Frontend Optimizations**
```
1. Code Splitting
   - React.lazy() for page components
   - Dynamic imports for modals

2. Image Optimization
   - Cloudinary transforms: ?w=200&q=auto&f=webp
   - Lazy load images: loading="lazy"

3. Bundle Size
   - npm run build → check dist/
   - Use dynamic imports for heavy libs

4. State Optimization
   - Zustand selectors to prevent re-renders
   - Memoize components: React.memo()

5. List Performance
   - Virtual scrolling for long lists
   - Infinite scroll instead of pagination
```

### **Backend Optimizations**
```
1. Database Indexing
   - Composite indexes on queries
   - TTL indexes for sessions

2. Query Optimization
   - Populate only needed fields
   - Pagination: skip + limit

3. Caching
   - Cache frequent queries
   - Use Redis for sessions

4. Response Compression
   - gzip middleware
   - JSON minification
```

---

## ✅ DEPLOYMENT CHECKLIST

### **Pre-Production**
```
Backend:
□ Set NODE_ENV=production
□ Enable HTTPS only
□ Set secure cookies
□ Enable CORS with specific origin
□ Hide sensitive errors
□ Enable logging
□ Set up monitoring (Sentry)
□ Database backups

Frontend:
□ Build optimization: npm run build
□ Remove console logs
□ Test PWA offline
□ Check bundle size
□ Enable gzip
□ Set cache headers
□ Test dark mode
```

### **Production Deployment**
```
Backend (e.g., Railway, Heroku):
□ Set all .env variables
□ Setup MongoDB Atlas
□ Enable automatic backups
□ Setup monitoring
□ Setup error logging
□ Configure auto-scaling

Frontend (e.g., Vercel, Netlify):
□ Connect GitHub repo
□ Set build command: npm run build
□ Set output dir: dist
□ Enable analytics
□ Setup error monitoring
□ Enable edge caching
```

---

## 🎓 LEARNING RESOURCES

### **By Technology**
- **React**: reactjs.org, react-patterns.com
- **Express**: expressjs.com, exploringjs.com
- **MongoDB**: mongodb.com/docs, mongoosejs.com
- **Socket.io**: socket.io/docs
- **Tailwind**: tailwindcss.com/docs
- **TypeScript**: typescriptlang.org/docs

### **Best Practices**
- Design patterns: refactoring.guru
- Performance: web.dev
- Security: owasp.org
- Accessibility: w3.org/WAI

---

## 📞 GETTING HELP

### **For Issues**
1. Check docs first
2. Search GitHub issues
3. Ask on Stack Overflow with tag
4. Create GitHub issue with reproduction steps

### **For Performance**
1. Lighthouse audit
2. Chrome DevTools > Performance tab
3. Network waterfall analysis
4. Database query profiling

### **For Security**
1. OWASP Top 10 checklist
2. npm audit report
3. Snyk dependency scanning
4. Penetration testing

---

**Last Updated:** April 29, 2026  
**Quick Reference v1.0**  
**For EcoMoji Team**
