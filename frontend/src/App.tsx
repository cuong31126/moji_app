import { BrowserRouter, Route, Routes } from "react-router";
import SignInPage from "./pages/SignInPage";
import ChatAppPage from "./pages/ChatAppPage";
import { Toaster } from "sonner";
import SignUpPage from "./pages/SignUpPage";
import SocialCallbackPage from "./pages/SocialCallbackPage";
import ProtectedRoute from "./components/auth/ProtectedRoute";
import { useThemeStore } from "./stores/useThemeStore";
import { useEffect } from "react";
import { useAuthStore } from "./stores/useAuthStore";
import { useSocketStore } from "./stores/useSocketStore";

function App() {
  const { isDark, setTheme } = useThemeStore();
  const { accessToken } = useAuthStore();
  const { connectSocket, disconnectSocket } = useSocketStore();

  useEffect(() => {
    setTheme(isDark);
  }, [isDark]);

  useEffect(() => {
    if (accessToken) {
      connectSocket();
    }

    return () => disconnectSocket();
  }, [accessToken]);

  return (
    <>
      <Toaster richColors />
      <BrowserRouter>
        <Routes>
          {/* public routes */}
          <Route
            path="/signin"
            element={<SignInPage />}
          />
          <Route
            path="/signup"
            element={<SignUpPage />}
          />
          <Route
            path="/auth/social-callback"
            element={<SocialCallbackPage />}
          />

          {/* protectect routes */}
          <Route element={<ProtectedRoute />}>
            <Route
              path="/"
              element={<ChatAppPage />}
            />
            <Route
              path="/map"
              element={<ChatAppPage view="map" />}
            />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
