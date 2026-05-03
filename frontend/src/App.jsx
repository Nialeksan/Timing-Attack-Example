import {Routes, Route, Navigate} from 'react-router-dom';
import {ProtectedRoute} from './components/ProtectedRoute.jsx';
import Login from './pages/Login.jsx';
import Register from './pages/Register.jsx';
import ForgotPassword from './pages/ForgotPassword.jsx';
import Dashboard from './pages/Dashboard.jsx';
import AdminDashboard from './pages/AdminDashboard.jsx';

export default function App() {
  return (
    <Routes>
      <Route path='/login' element={<Login />} />
      <Route path='/register' element={<Register />} />
      <Route path='/forgot-password' element={<ForgotPassword />} />
      <Route path='/dashboard' element={
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      } />
      <Route path='/admin' element={
        <ProtectedRoute requireAdmin={true}>
          <AdminDashboard />
        </ProtectedRoute>
      } />
      <Route path='*' element={<Navigate to={"/login"} replace />} />
    </Routes>
  );
}