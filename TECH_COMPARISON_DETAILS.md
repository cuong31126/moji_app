# 🔧 EcoMoji - Công nghệ Chi Tiết & So Sánh

---

## 📊 SO SÁNH CÔNG NGHỆ

### **Backend Framework Comparison**
| Tiêu chí | Express 5 | FastAPI | Django |
|----------|-----------|---------|--------|
| **Language** | JavaScript (Node.js) | Python | Python |
| **Learning Curve** | Dễ | Trung bình | Khó |
| **Performance** | Cao | Rất cao | Trung bình |
| **Ecosystem** | Rất lớn (npm) | Nhỏ | Rất lớn (PyPI) |
| **Real-time (Socket.io)** | ✅ Native | ⚠️ Cần WebSocket | ⚠️ Cần Celery |
| **Scalability** | Tốt (cluster mode) | Xuất sắc | Tốt |
| **Deployment** | Dễ (Node.js) | Trung bình | Dễ (Docker) |
| **Cost** | ✅ Free | ✅ Free | ✅ Free |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn Express:**
- Được sử dụng rộng rãi trong Node.js ecosystem
- Socket.io hỗ trợ tốt nhất trên Express
- Một team có thể code cả frontend (React) và backend (Express) JavaScript
- Deployment dễ (Heroku, Vercel, Railway)

---

### **Frontend Framework Comparison**
| Tiêu chí | React 19 | Vue 3 | Svelte |
|----------|---------|-------|--------|
| **Learning Curve** | Trung bình | Dễ | Dễ |
| **Performance** | Cao | Cao | Rất cao |
| **Bundle Size** | 42KB (gzip) | 34KB | 12KB |
| **Ecosystem** | Khổng lồ (npm) | Trung bình | Nhỏ |
| **Component Reusability** | ✅ Xuất sắc | ✅ Tốt | ✅ Tốt |
| **State Management** | Zustand/Redux | Pinia | Svelte stores |
| **Routing** | React Router | Vue Router | SvelteKit |
| **TypeScript Support** | ✅ Tốt | ✅ Tốt | ✅ Tốt |
| **Community Support** | Lớn | Trung bình | Nhỏ |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn React:**
- Community lớn nhất, dễ tìm developer
- Ecosystem phong phú (components, libraries)
- Vite + React setup siêu nhanh
- Radix UI, shadcn/ui hỗ trợ tốt

---

### **State Management Comparison**
| Tiêu chí | Zustand | Redux | Context API |
|----------|---------|-------|-------------|
| **Learning Curve** | ✅ Dễ | Khó | Trung bình |
| **Bundle Size** | 1.2KB | 4.3KB | Built-in |
| **DevTools** | Có | Xuất sắc | Không |
| **Async Support** | ✅ Tốt | Cần middleware | ✅ Tốt |
| **Performance** | Xuất sắc | Tốt | Tốt |
| **Scalability** | ✅ Tốt | ✅ Lớn | Tốt |
| **Boilerplate** | Ít | Nhiều | Ít |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn Zustand:**
- Cực kỳ đơn giản, ít boilerplate
- Giản tinh nhẹ (1.2KB), không overhead
- DevTools tốt, dễ debug
- Phù hợp với MVP nhanh

---

### **CSS Framework Comparison**
| Tiêu chí | Tailwind 4 | Bootstrap 5 | Material UI |
|----------|-----------|-----------|------------|
| **Approach** | Utility-first | Component-based | Component-based |
| **Learning** | Trung bình | Dễ | Khó |
| **Customization** | ✅ Rất cao | Trung bình | Cao |
| **Bundle Size** | 15KB (purged) | 30KB | 50KB+ |
| **Dark Mode** | ✅ Built-in | Manual | Built-in |
| **Responsive** | ✅ Xuất sắc | ✅ Tốt | Tốt |
| **Component Quality** | Cần UI lib | ✅ Tốt | ✅ Xuất sắc |
| **Design System** | DIY | Built-in | Built-in |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn Tailwind CSS:**
- Flexibility cao, dễ customize
- Vite integration xuất sắc
- Dark mode support tự nhiên
- + Radix UI = perfect combo

---

### **UI Component Library Comparison**
| Tiêu chí | Radix UI | Material UI | Headless UI |
|----------|---------|-----------|------------|
| **Accessibility** | ✅ Xuất sắc (WAI-ARIA) | Tốt | Tốt |
| **Customization** | ✅ Dễ | Khó (Material style) | ✅ Rất dễ |
| **Styling** | Any (Tailwind friendly) | Material CSS | Any |
| **Component Quality** | Xuất sắc | Xuất sắc | Tốt |
| **Bundle Size** | 20KB | 50KB+ | 15KB |
| **Dark Mode** | Manual (easy) | Built-in | Manual |
| **Documentation** | ✅ Tốt | ✅ Tốt | ✅ Tốt |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn Radix UI:**
- Headless = full control styling
- WAI-ARIA compliant (accessibility)
- Perfect với Tailwind CSS
- Lightweight, performance tốt

---

### **Real-time Communication Comparison**
| Tiêu chí | Socket.io | WebSocket | Pusher |
|----------|-----------|-----------|--------|
| **Learning** | Dễ | Trung bình | Dễ |
| **Setup** | ✅ Dễ | ✅ Dễ | SaaS |
| **Features** | Broadcast, rooms | Low-level | Channels, presence |
| **Fallback** | ✅ Auto polling | Không | ✅ Auto |
| **Scalability** | Adapter needed | Redis needed | Unlimited |
| **Cost** | ✅ Free | ✅ Free | $ (SaaS) |
| **Dev Time** | Nhanh | Chậm | Nhanh |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn Socket.io:**
- Automatic fallback (polling/SSE)
- Rooms & namespaces built-in
- Broadcasting dễ dàng
- Free, không vendor lock-in

---

### **Database Comparison**
| Tiêu chí | MongoDB | PostgreSQL | Firebase |
|----------|---------|-----------|----------|
| **Data Model** | Document (JSON) | Relational (SQL) | Hybrid |
| **Flexibility** | ✅ Cao | Cứng nhắc | Trung bình |
| **Query Power** | Tốt | ✅ Xuất sắc | Hạn chế |
| **Scaling** | ✅ Horizontal | Vertical | Automatic |
| **ACID Transactions** | ⚠️ Limited | ✅ Full | Partial |
| **Cost** | ✅ Free | ✅ Free | $ (SaaS) |
| **Setup Time** | Nhanh | Trung bình | Siêu nhanh |
| **Performance** | Tốt (indexed) | Xuất sắc | Tốt |
| **EcoMoji Choice** | ✅ Chọn | ❌ | ❌ |

**Lý do chọn MongoDB:**
- Document model phù hợp với chat messages
- Flexible schema (conversations, reports)
- Scaling horizontal dễ
- Mongoose ORM đơn giản

---

## 🔄 REQUEST/RESPONSE FLOW EXAMPLES

### **Example 1: Login with Username**
```
REQUEST:
POST /api/auth/signin
Content-Type: application/json

{
  "username": "ecomoji_user",
  "password": "securepassword123"
}

RESPONSE (200 OK):
{
  "message": "User Người Dùng đã đăng nhập",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "_id": "507f1f77bcf86cd799439011",
    "username": "ecomoji_user",
    "email": "user@example.com",
    "displayName": "Người Dùng",
    "avatarUrl": "https://res.cloudinary.com/...",
    "bio": "🌍 Bảo vệ môi trường",
    "authProviders": [
      { "provider": "local", "providerId": "ecomoji_user" }
    ]
  }
}

RESPONSE HEADERS:
Set-Cookie: refreshToken=eyJhbGciOiJIUzI1NiIs...; HttpOnly; SameSite=Lax; Path=/
```

### **Example 2: Send Chat Message**
```
SOCKET EMIT:
socket.emit("send-message", {
  conversationId: "507f1f77bcf86cd799439012",
  content: "Mình thấy thùng rác ở công viên Tao Đàn",
  messageType: "text"
})

SERVER PROCESSES:
1. Verify socket auth (userId from JWT)
2. Create Message document:
{
  _id: "507f1f77bcf86cd799439013",
  conversationId: "507f1f77bcf86cd799439012",
  senderId: "507f1f77bcf86cd799439011",
  content: "Mình thấy thùng rác ở công viên Tao Đàn",
  messageType: "text",
  createdAt: "2026-04-29T10:30:00Z"
}
3. Update Conversation:
   - lastMessage = this message
   - lastMessageAt = now
4. Broadcast to all participants

SERVER EMIT (to all in room):
socket.emit("new-message", {
  _id: "507f1f77bcf86cd799439013",
  conversationId: "507f1f77bcf86cd799439012",
  senderId: "507f1f77bcf86cd799439011",
  sender: {
    _id: "507f1f77bcf86cd799439011",
    displayName: "Người Dùng",
    avatarUrl: "..."
  },
  content: "Mình thấy thùng rác ở công viên Tao Đàn",
  messageType: "text",
  createdAt: "2026-04-29T10:30:00Z",
  isOwn: true/false (depends on receiver)
})
```

### **Example 3: Trash Report with Location**
```
REQUEST:
POST /api/reports
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{
  "title": "Thùng rác vỡ tại công viên Tao Đàn",
  "description": "Có rác nhựa và chai thủy tinh nằm lăn lóc quanh thùng rác",
  "type": "plastic",
  "severity": "high",
  "location": {
    "lat": 21.0285,
    "lng": 105.8542,
    "address": "Công viên Tao Đàn, Hà Nội"
  },
  "images": ["cloudinary_url_1", "cloudinary_url_2"]
}

RESPONSE (201 CREATED):
{
  "_id": "507f1f77bcf86cd799439014",
  "title": "Thùng rác vỡ tại công viên Tao Đàn",
  "description": "...",
  "type": "plastic",
  "severity": "high",
  "status": "ACTIVE",
  "location": {
    "type": "Point",
    "coordinates": [105.8542, 21.0285],
    "lat": 21.0285,
    "lng": 105.8542
  },
  "reportedBy": "507f1f77bcf86cd799439011",
  "images": [...],
  "views": ["507f1f77bcf86cd799439011"],
  "confirmations": [
    {
      "userId": "507f1f77bcf86cd799439011",
      "createdAt": "2026-04-29T10:30:00Z"
    }
  ],
  "cleanup": null,
  "createdAt": "2026-04-29T10:30:00Z"
}
```

---

## 📦 DEPENDENCIES VERSION LOCK

### **Backend Lock**
```json
{
  "bcrypt": "^6.0.0",
  "cloudinary": "^2.8.0",
  "cookie-parser": "^1.4.7",
  "cors": "^2.8.5",
  "dotenv": "^17.2.3",
  "express": "^5.1.0",
  "jsonwebtoken": "^9.0.2",
  "mongoose": "^8.19.0",
  "multer": "^2.0.2",
  "passport": "^0.7.0",
  "passport-facebook": "^3.0.0",
  "passport-github2": "^0.1.12",
  "passport-google-oauth20": "^2.0.0",
  "socket.io": "^4.8.1",
  "swagger-ui-express": "^5.0.1"
}
```

### **Frontend Lock**
```json
{
  "@emoji-mart/data": "^1.2.1",
  "@emoji-mart/react": "^1.1.1",
  "@hookform/resolvers": "^5.2.2",
  "@radix-ui/react-*": "^1.1.x",
  "@tailwindcss/vite": "^4.1.18",
  "@types/leaflet": "^1.9.21",
  "axios": "^1.13.2",
  "class-variance-authority": "^0.7.1",
  "clsx": "^2.1.1",
  "emoji-mart": "^5.6.0",
  "leaflet": "^1.9.4",
  "lucide-react": "^0.562.0",
  "react": "^19.2.0",
  "react-dom": "^19.2.0",
  "react-hook-form": "^7.69.0",
  "react-infinite-scroll-component": "^6.1.1",
  "react-leaflet": "^5.0.0",
  "react-router": "^7.11.0",
  "socket.io-client": "^4.8.3",
  "sonner": "^2.0.7",
  "tailwind-merge": "^3.4.0",
  "tailwindcss": "^4.1.18",
  "tailwindcss-animate": "^1.0.7",
  "zod": "^4.2.1",
  "zustand": "^5.0.9"
}
```

---

## 🎯 PERFORMANCE METRICS

### **Frontend Performance**
```
Lighthouse Scores (Target):
- Performance: 90+
- Accessibility: 95+
- Best Practices: 90+
- SEO: 90+

Bundle Size Analysis:
- React + React-DOM: 42KB
- Tailwind CSS: 15KB (purged)
- Radix UI: 20KB
- Socket.io client: 18KB
- Other libs: 25KB
- ----------------------------------
- Total: ~120KB (gzipped)

Page Load Time:
- First Contentful Paint (FCP): < 1.5s
- Largest Contentful Paint (LCP): < 2.5s
- Cumulative Layout Shift (CLS): < 0.1
```

### **Backend Performance**
```
Response Time:
- API endpoint: < 100ms
- Database query: < 50ms
- Socket event: < 10ms

Throughput:
- Concurrent connections: 10,000+
- Messages/second: 1,000+
- Database ops/second: 5,000+

Memory Usage:
- Node process: ~150-200MB
- Socket.io connections: ~1MB per 100 connections
```

---

## 🔐 SECURITY BEST PRACTICES

### **Authentication Security**
```
✅ Implemented:
- Password hashing: bcrypt (10 rounds)
- JWT tokens: RS256 signing
- Refresh tokens: httpOnly cookies
- CSRF protection: SameSite=Lax
- CORS credentials: true

⚠️ Recommended:
- Rate limiting: express-rate-limit
- Input validation: joi/zod
- SQL injection: Mongoose prevents
- XSS protection: Content-Security-Policy
- HTTPS: Required in production
```

### **API Security**
```
✅ Implemented:
- Authentication middleware
- Protected routes
- Role-based access (implicit)
- Sensitive data: exclude passwords

⚠️ Recommended:
- API versioning: /api/v1/
- Request size limit: 10MB
- Timeout handling: 30s
- Error messages: generic in prod
- Logging: all requests
```

---

## 🚀 DEPLOYMENT ARCHITECTURE

### **Production Setup**
```
┌─────────────────────────────────────────┐
│     Client Browser (React SPA)          │
│     - Static hosted on CDN              │
│     - Service Worker for PWA            │
└───────────────┬───────────────┬─────────┘
                │               │
        ┌───────┴───────┐       │
        │               │       │
    ┌───┴────┐      ┌──┴───┐   │
    │ REST   │      │Socket│   │
    │HTTP/2  │      │.io   │   │
    │        │      │WSS   │   │
    └───┬────┘      └──┬───┘   │
        │               │       │
   ┌────┴───────────────┴───────┘
   │
   │  Load Balancer (Nginx/HAProxy)
   │
   ├─────────────┬─────────────┐
   │             │             │
  ┌┴────────┐ ┌─┴────────┐ ┌──┴─────┐
  │ Express │ │ Express  │ │ Express │
  │ Node 1  │ │ Node 2   │ │ Node 3  │
  └┬───────┬┘ └─┬──────┬─┘ └──┬──┬──┘
   │       │    │      │      │  │
   │   ┌───┴────┴──────┴──────┴──┘
   │   │
   │ ┌─┴─────────────────┐
   │ │  Redis Adapter    │
   │ │  (Socket.io)      │
   │ └─────────────────┘
   │
   └─────────────────┐
                     │
      ┌──────────────┴──────────────┐
      │                             │
  ┌───┴─────┐              ┌───────┴──┐
  │ MongoDB  │              │ Cloudinary
  │ Replica  │              │ CDN (Images)
  │ Set      │              └───────────┘
  └──────────┘
```

---

## 📞 SUPPORT & RESOURCES

### **Documentation Links**
- React: https://react.dev
- Express: https://expressjs.com
- MongoDB/Mongoose: https://mongoosejs.com
- Socket.io: https://socket.io
- Tailwind CSS: https://tailwindcss.com
- Radix UI: https://radix-ui.com
- Zustand: https://github.com/pmndrs/zustand
- Vite: https://vitejs.dev

### **Community Channels**
- GitHub Issues: Report bugs
- Stack Overflow: Ask questions
- Discord communities: React, Node.js, MongoDB
- Reddit: r/reactjs, r/node, r/mongodb

---

**Last Updated:** April 29, 2026  
**Version:** 1.0  
**Maintained by:** EcoMoji Development Team
