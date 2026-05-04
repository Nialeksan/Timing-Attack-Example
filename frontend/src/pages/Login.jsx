import { useState } from "react";
import {useNavigate, Link} from 'react-router-dom';

export default function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [secure, setSecure] = useState(false);
    const navigate = useNavigate();

    async function handleSubmit(e) {
        e.preventDefault(); // Prevents the form to relods the page (HTML reloads by default)
        setError(''); // Cleans previous error before trying again

        const endpoint = secure ? '/auth/login-secure' : '/auth/login';
        const res = await fetch(`${import.meta.env.VITE_API_URL}${endpoint}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include', // This is important so that the browser can store the cookie sent by the backend
            body: JSON.stringify({email, password}),
        });

        if (res.ok) {
            navigate('/dashboard');
        } else {
            const data = await res.json();
            setError(data.message ?? 'Login failed');
        }
    }

    return (
        <div className="auth-page">
            <div className="auth-card">
                <h1 className="auth-title">PIA — Secure Portal</h1>
                <h2 className="auth-subtitle">Sign in</h2>

                {/* Only renders error paragraph if error isn't empty string */}
                {error && <p className="form-error">{error}</p>}

                <div className="toggle-wrapper">
                    <label htmlFor="secureToggle" className="toggle-label">
                        {secure ? '🔒 Secure' : '🔓 Vulnerable'}
                    </label>
                    <input 
                        className="toggle-input"
                        id="secureToggle"
                        type="checkbox"
                        checked={secure}
                        onChange={() => setSecure(s => !s)} 
                    />
                </div>

                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input 
                            id="email"
                            type="email"
                            value={email}
                            onChange={e => setEmail(e.target.value)}
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input 
                            id="password"
                            type="password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            required
                        />
                    </div>
                    <button className="btn btn--primary" type="submit">Sign in</button>
                </form>
                <p className="auth-links">
                    <Link to="/forgot-password">Forgot your password?</Link>
                </p>
                <p className="auth-links">
                    Don't have an account? <Link to="/register">Register</Link>
                </p>
            </div>
        </div>
    );
}